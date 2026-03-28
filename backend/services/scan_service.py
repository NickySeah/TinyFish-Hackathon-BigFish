from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Any

from supabase import Client, create_client

from config import settings


class ScanServiceError(RuntimeError):
    """Raised when scan persistence or query operations fail."""


@dataclass(frozen=True)
class ScanResult:
    id: str
    url: str
    expiry_date: str


def get_supabase_client() -> Client:
    """Initialize Supabase client using SUPABASE_URL and SUPABASE_KEY env vars."""
    if not settings.supabase_url or not settings.supabase_key:
        raise ScanServiceError("SUPABASE_URL and SUPABASE_KEY are required")
    return create_client(settings.supabase_url, settings.supabase_key)


def process_url_scan(
    url: str,
    user_id: str | None,
    openai_data: dict[str, Any],
    vt_data: dict[str, Any],
) -> dict[str, Any]:
    """
    Insert a scan row into scans with JSON payloads.
    user_id is accepted for backward compatibility but is not persisted.
    """
    try:
        client = get_supabase_client()

        _ = user_id

        scan_payload: dict[str, Any] = {
            "url": url,
            "expiry_date": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
            "openai_raw": openai_data,
            "vt_raw": vt_data,
        }

        scan_response = client.table("scans").insert(scan_payload).execute()
        if not scan_response.data:
            raise ScanServiceError("Scan insert succeeded but no row was returned")

        scan_row = scan_response.data[0]
        return {
            "id": scan_row.get("id"),
            "url": scan_row.get("url", url),
            "expiry_date": scan_row.get("expiry_date"),
        }
    except Exception as exc:
        raise ScanServiceError(f"Failed to process URL scan: {str(exc)}") from exc


def fetch_recent_scans(limit: int = 25, user_id: str | None = None) -> list[dict[str, Any]]:
    """
    Fetch recent scans from scans table.
    user_id is accepted for backward compatibility but is not used.
    """
    try:
        client = get_supabase_client()

        _ = user_id

        query = client.table("scans").select("*").order("scanned_at", desc=True).limit(limit)

        response = query.execute()
        rows = response.data or []
        return rows
    except Exception as exc:
        raise ScanServiceError(f"Failed to fetch recent scans: {str(exc)}") from exc
