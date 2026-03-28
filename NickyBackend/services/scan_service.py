from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from supabase import Client, create_client

from config import settings


class ScanServiceError(RuntimeError):
    """Raised when scan persistence or query operations fail."""


@dataclass(frozen=True)
class ScanResult:
    id: str
    url_id: str
    final_verdict: str
    risk_score: int


def get_supabase_client() -> Client:
    """Initialize Supabase client using SUPABASE_URL and SUPABASE_KEY env vars."""
    if not settings.supabase_url or not settings.supabase_key:
        raise ScanServiceError("SUPABASE_URL and SUPABASE_KEY are required")
    return create_client(settings.supabase_url, settings.supabase_key)


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.lower()


def _calculate_final_verdict(tinyfish_data: dict[str, Any], vt_data: dict[str, Any]) -> tuple[str, int]:
    tinyfish_verdict = str(tinyfish_data.get("verdict", "")).upper()

    vt_malicious_votes = int(vt_data.get("malicious_votes") or 0)
    vt_total_votes = int(vt_data.get("total_votes") or 0)
    vt_ratio = (vt_malicious_votes / vt_total_votes) if vt_total_votes > 0 else 0

    if tinyfish_verdict == "MALICIOUS" or vt_malicious_votes >= 5 or vt_ratio >= 0.3:
        return "MALICIOUS", min(100, 70 + vt_malicious_votes * 5)
    if tinyfish_verdict == "SUSPICIOUS" or vt_malicious_votes > 0:
        return "SUSPICIOUS", min(100, 35 + vt_malicious_votes * 8)
    if tinyfish_verdict == "SAFE" and vt_malicious_votes == 0:
        return "SAFE", 0
    return "PENDING", 10


def process_url_scan(
    url: str,
    user_id: str | None,
    tinyfish_data: dict[str, Any],
    vt_data: dict[str, Any],
) -> dict[str, Any]:
    """
    1) Upsert url into urls table.
    2) Insert a scan row into scans with JSON payloads and computed final verdict.
    """
    try:
        client = get_supabase_client()

        domain = _extract_domain(url)

        upsert_response = (
            client.table("urls")
            .upsert({"original_url": url, "domain": domain}, on_conflict="original_url")
            .execute()
        )

        if not upsert_response.data:
            raise ScanServiceError("URL upsert succeeded but no row was returned")

        url_id = upsert_response.data[0].get("id")
        if not url_id:
            existing = (
                client.table("urls")
                .select("id")
                .eq("original_url", url)
                .limit(1)
                .execute()
            )
            if not existing.data:
                raise ScanServiceError("Unable to resolve url_id after upsert")
            url_id = existing.data[0]["id"]

        final_verdict, risk_score = _calculate_final_verdict(tinyfish_data, vt_data)

        tinyfish_verdict = tinyfish_data.get("verdict")
        vt_verdict = vt_data.get("verdict")
        vt_malicious_votes = int(vt_data.get("malicious_votes") or 0)
        vt_total_votes = int(vt_data.get("total_votes") or 0)

        scan_payload: dict[str, Any] = {
            "url_id": url_id,
            "user_id": user_id,
            "tinyfish_verdict": tinyfish_verdict,
            "tinyfish_raw": tinyfish_data,
            "vt_verdict": vt_verdict,
            "vt_malicious_votes": vt_malicious_votes,
            "vt_total_votes": vt_total_votes,
            "vt_raw": vt_data,
            "final_verdict": final_verdict,
            "risk_score": risk_score,
        }

        scan_response = client.table("scans").insert(scan_payload).execute()
        if not scan_response.data:
            raise ScanServiceError("Scan insert succeeded but no row was returned")

        scan_row = scan_response.data[0]
        return {
            "id": scan_row.get("id"),
            "url_id": url_id,
            "final_verdict": scan_row.get("final_verdict", final_verdict),
            "risk_score": scan_row.get("risk_score", risk_score),
        }
    except Exception as exc:
        raise ScanServiceError(f"Failed to process URL scan: {str(exc)}") from exc


def fetch_recent_scans(limit: int = 25, user_id: str | None = None) -> list[dict[str, Any]]:
    """
    Fetch recent scans with joined URL metadata.
    Returns scan columns plus urls.original_url and urls.domain.
    """
    try:
        client = get_supabase_client()

        query = (
            client.table("scans")
            .select(
                "id,url_id,user_id,tinyfish_verdict,tinyfish_raw,vt_verdict,vt_malicious_votes,vt_total_votes,vt_raw,final_verdict,risk_score,scanned_at,urls(original_url,domain)"
            )
            .order("scanned_at", desc=True)
            .limit(limit)
        )

        if user_id:
            query = query.eq("user_id", user_id)

        response = query.execute()
        rows = response.data or []

        normalized: list[dict[str, Any]] = []
        for row in rows:
            url_meta = row.get("urls") or {}
            normalized.append(
                {
                    "id": row.get("id"),
                    "url_id": row.get("url_id"),
                    "user_id": row.get("user_id"),
                    "tinyfish_verdict": row.get("tinyfish_verdict"),
                    "tinyfish_raw": row.get("tinyfish_raw"),
                    "vt_verdict": row.get("vt_verdict"),
                    "vt_malicious_votes": row.get("vt_malicious_votes"),
                    "vt_total_votes": row.get("vt_total_votes"),
                    "vt_raw": row.get("vt_raw"),
                    "final_verdict": row.get("final_verdict"),
                    "risk_score": row.get("risk_score"),
                    "scanned_at": row.get("scanned_at"),
                    "original_url": url_meta.get("original_url"),
                    "domain": url_meta.get("domain"),
                }
            )

        return normalized
    except Exception as exc:
        raise ScanServiceError(f"Failed to fetch recent scans: {str(exc)}") from exc
