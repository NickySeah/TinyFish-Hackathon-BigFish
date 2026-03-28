import os
from uuid import UUID
from urllib.parse import urlparse

import psycopg2
from fastapi import FastAPI, HTTPException, Query, status

from config import settings, validate_settings
from schemas import ScanCreate, ScanUpdate, UrlCreate, UrlUpdate
from supabase_client import get_anon_client


app = FastAPI(title="URL Analysis API", version="1.1.0")


try:
    validate_settings()
except RuntimeError as exc:
    raise RuntimeError(str(exc)) from exc


DATABASE_URL = os.getenv("DATABASE_URL", settings.database_url)


VALID_FINAL_VERDICTS = {"SAFE", "SUSPICIOUS", "MALICIOUS", "PENDING", "ERROR"}


def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


def validate_risk_score(risk_score: int | None) -> None:
    if risk_score is None:
        return
    if risk_score < 0 or risk_score > 100:
        raise HTTPException(status_code=400, detail="risk_score must be between 0 and 100")


def extract_domain(original_url: str) -> str | None:
    parsed = urlparse(original_url)
    if parsed.netloc:
        return parsed.netloc.lower()
    # Fallback for URLs entered without scheme.
    parsed = urlparse(f"https://{original_url}")
    return parsed.netloc.lower() or None


def get_or_create_url_record(original_url: str) -> dict:
    client = get_anon_client()

    existing = (
        client.table("urls")
        .select("*")
        .eq("original_url", original_url)
        .limit(1)
        .execute()
    )

    if existing.data:
        return existing.data[0]

    payload = {
        "original_url": original_url,
        "domain": extract_domain(original_url),
    }
    created = client.table("urls").insert(payload).execute()
    if not created.data:
        raise HTTPException(status_code=500, detail="Failed to create URL record")
    return created.data[0]


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/db")
def database_health_check() -> dict[str, str]:
    try:
        conn = get_db_connection()
        conn.close()
        return {"database": "connected"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(exc)}") from exc


@app.get("/urls")
def list_urls():
    try:
        client = get_anon_client()
        response = client.table("urls").select("*").order("created_at", desc=True).execute()
        return {"data": response.data}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch urls: {str(exc)}") from exc


@app.get("/urls/{url_id}")
def get_url_by_id(url_id: UUID):
    try:
        client = get_anon_client()
        response = (
            client.table("urls")
            .select("*")
            .eq("id", str(url_id))
            .limit(1)
            .execute()
        )

        if not response.data:
            raise HTTPException(status_code=404, detail="URL not found")

        return {"data": response.data[0]}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch url: {str(exc)}") from exc


@app.get("/urls/by-original")
def get_url_by_original(original_url: str = Query(..., description="Exact original URL string")):
    try:
        client = get_anon_client()
        response = (
            client.table("urls")
            .select("*")
            .eq("original_url", original_url)
            .limit(1)
            .execute()
        )

        if not response.data:
            raise HTTPException(status_code=404, detail="URL not found")

        return {"data": response.data[0]}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch url by original_url: {str(exc)}") from exc


@app.post("/urls", status_code=status.HTTP_201_CREATED)
def create_url(payload: UrlCreate):
    try:
        values = payload.model_dump(exclude_none=True)
        values.setdefault("domain", extract_domain(values["original_url"]))

        client = get_anon_client()
        response = client.table("urls").insert(values).execute()
        return {"data": response.data}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to create url: {str(exc)}") from exc


@app.patch("/urls/{url_id}")
def update_url(url_id: UUID, payload: UrlUpdate):
    try:
        values = payload.model_dump(exclude_none=True)

        if not values:
            raise HTTPException(status_code=400, detail="No updatable fields provided")

        if "original_url" in values and "domain" not in values:
            values["domain"] = extract_domain(values["original_url"])

        client = get_anon_client()
        response = (
            client.table("urls")
            .update(values)
            .eq("id", str(url_id))
            .execute()
        )

        if not response.data:
            raise HTTPException(status_code=404, detail="URL not found")

        return {"data": response.data}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to update url: {str(exc)}") from exc


@app.delete("/urls/{url_id}")
def delete_url(url_id: UUID):
    try:
        client = get_anon_client()
        response = (
            client.table("urls")
            .delete()
            .eq("id", str(url_id))
            .execute()
        )

        if not response.data:
            raise HTTPException(status_code=404, detail="URL not found")

        return {"message": "URL deleted", "data": response.data}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete url: {str(exc)}") from exc


@app.get("/urls/{url_id}/scans")
def list_scans_for_url(url_id: UUID):
    try:
        client = get_anon_client()
        response = (
            client.table("scans")
            .select("*,urls(original_url,domain)")
            .eq("url_id", str(url_id))
            .order("scanned_at", desc=True)
            .execute()
        )
        return {"data": response.data}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch scans for URL: {str(exc)}") from exc


@app.get("/scans")
def list_scans():
    try:
        client = get_anon_client()
        response = (
            client.table("scans")
            .select("*,urls(original_url,domain)")
            .order("scanned_at", desc=True)
            .execute()
        )
        return {"data": response.data}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch scans: {str(exc)}") from exc


@app.get("/scans/{scan_id}")
def get_scan_by_id(scan_id: UUID):
    try:
        client = get_anon_client()
        response = (
            client.table("scans")
            .select("*,urls(original_url,domain)")
            .eq("id", str(scan_id))
            .limit(1)
            .execute()
        )

        if not response.data:
            raise HTTPException(status_code=404, detail="Scan not found")

        return {"data": response.data[0]}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch scan: {str(exc)}") from exc


@app.post("/scans", status_code=status.HTTP_201_CREATED)
def create_scan(payload: ScanCreate):
    try:
        validate_risk_score(payload.risk_score)

        values = payload.model_dump(exclude_none=True)

        client = get_anon_client()
        response = client.table("scans").insert(values).execute()
        return {"data": response.data}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(exc)}") from exc


@app.patch("/scans/{scan_id}")
def update_scan(scan_id: UUID, payload: ScanUpdate):
    try:
        values = payload.model_dump(exclude_none=True)
        validate_risk_score(values.get("risk_score"))

        if not values:
            raise HTTPException(status_code=400, detail="No updatable fields provided")

        if "final_verdict" in values and values["final_verdict"] not in VALID_FINAL_VERDICTS:
            raise HTTPException(status_code=400, detail="Invalid final_verdict")

        client = get_anon_client()
        response = (
            client.table("scans")
            .update(values)
            .eq("id", str(scan_id))
            .execute()
        )

        if not response.data:
            raise HTTPException(status_code=404, detail="Scan not found")

        return {"data": response.data}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to update scan: {str(exc)}") from exc


@app.delete("/scans/{scan_id}")
def delete_scan(scan_id: UUID):
    try:
        client = get_anon_client()
        response = (
            client.table("scans")
            .delete()
            .eq("id", str(scan_id))
            .execute()
        )

        if not response.data:
            raise HTTPException(status_code=404, detail="Scan not found")

        return {"message": "Scan deleted", "data": response.data}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete scan: {str(exc)}") from exc


@app.post("/analyze", status_code=status.HTTP_201_CREATED)
def analyze_url(original_url: str = Query(..., description="URL to analyze"), user_id: UUID | None = None):
    """
    Creates or reuses the URL row, then creates a new scan row with a PENDING verdict.
    The worker/integration layer can later update this scan with Tinyfish / VirusTotal results.
    """
    try:
        url_row = get_or_create_url_record(original_url)

        scan_payload = {
            "url_id": url_row["id"],
            "user_id": str(user_id) if user_id else None,
            "final_verdict": "PENDING",
        }

        client = get_anon_client()
        response = client.table("scans").insert(scan_payload).execute()
        if not response.data:
            raise HTTPException(status_code=500, detail="Failed to create analysis job")

        return {
            "message": "Analysis created",
            "url": url_row,
            "scan": response.data[0],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to analyze url: {str(exc)}") from exc


@app.get("/analyze/{scan_id}")
def get_analysis_result(scan_id: UUID):
    """Convenience endpoint for frontend polling."""
    return get_scan_by_id(scan_id)


@app.get("/stats/summary")
def get_summary_stats():
    try:
        client = get_anon_client()
        scans = client.table("scans").select("id,final_verdict,risk_score").execute().data or []

        total_scans = len(scans)
        safe_count = sum(1 for row in scans if row.get("final_verdict") == "SAFE")
        suspicious_count = sum(1 for row in scans if row.get("final_verdict") == "SUSPICIOUS")
        malicious_count = sum(1 for row in scans if row.get("final_verdict") == "MALICIOUS")
        pending_count = sum(1 for row in scans if row.get("final_verdict") == "PENDING")
        error_count = sum(1 for row in scans if row.get("final_verdict") == "ERROR")

        risk_values = [row["risk_score"] for row in scans if row.get("risk_score") is not None]
        avg_risk_score = round(sum(risk_values) / len(risk_values), 2) if risk_values else None

        return {
            "data": {
                "total_scans": total_scans,
                "safe_count": safe_count,
                "suspicious_count": suspicious_count,
                "malicious_count": malicious_count,
                "pending_count": pending_count,
                "error_count": error_count,
                "average_risk_score": avg_risk_score,
            }
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch summary stats: {str(exc)}") from exc


@app.get("/stats/domains/{domain}")
def get_domain_stats(domain: str):
    try:
        client = get_anon_client()
        response = (
            client.table("scans")
            .select("id,final_verdict,urls!inner(domain,original_url)")
            .eq("urls.domain", domain.lower())
            .execute()
        )
        rows = response.data or []

        return {
            "data": {
                "domain": domain.lower(),
                "total_scans": len(rows),
                "malicious_count": sum(1 for row in rows if row.get("final_verdict") == "MALICIOUS"),
                "suspicious_count": sum(1 for row in rows if row.get("final_verdict") == "SUSPICIOUS"),
                "safe_count": sum(1 for row in rows if row.get("final_verdict") == "SAFE"),
                "pending_count": sum(1 for row in rows if row.get("final_verdict") == "PENDING"),
                "error_count": sum(1 for row in rows if row.get("final_verdict") == "ERROR"),
            }
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch domain stats: {str(exc)}") from exc
