import os
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg2
from fastapi import FastAPI, HTTPException, Query, status

from config import settings, validate_settings
from schemas import ScanCreate, ScanUpdate
from supabase_client import get_anon_client


app = FastAPI(title="URL Analysis API", version="1.3.0")


try:
    validate_settings()
except RuntimeError as exc:
    raise RuntimeError(str(exc)) from exc


DATABASE_URL = os.getenv("DATABASE_URL", settings.database_url)
DEFAULT_SCAN_EXPIRY_DAYS = 7


def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


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


@app.get("/url-sources")
def list_url_sources():
    try:
        client = get_anon_client()
        response = client.table("url_sources").select("*").order("created_at", desc=True).execute()
        return {"data": response.data}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch url sources: {str(exc)}") from exc


@app.get("/url-sources/by-url")
def get_url_sources_by_url(url: str = Query(..., description="Exact URL string from url_sources.url")):
    try:
        client = get_anon_client()
        response = (
            client.table("url_sources")
            .select("*")
            .eq("url", url)
            .order("created_at", desc=True)
            .execute()
        )

        if not response.data:
            raise HTTPException(status_code=404, detail="No url_sources records found for this url")

        return {"data": response.data}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch url sources by url: {str(exc)}") from exc


@app.get("/scans")
def list_scans():
    try:
        client = get_anon_client()
        response = client.table("scans").select("*").order("scanned_at", desc=True).execute()
        return {"data": response.data}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch scans: {str(exc)}") from exc


@app.get("/scans/{scan_id}")
def get_scan_by_id(scan_id: UUID):
    try:
        client = get_anon_client()
        response = (
            client.table("scans")
            .select("*")
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
        values = payload.model_dump(mode="json", exclude_unset=True, exclude_none=True)

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
        values = payload.model_dump(mode="json", exclude_none=True)

        if not values:
            raise HTTPException(status_code=400, detail="No updatable fields provided")

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
def analyze_url(original_url: str = Query(..., description="URL to analyze")):
    """
    Records the input URL in url_sources, then creates a scan row with required fields.
    The worker/integration layer can later update this scan with OpenAI / VirusTotal JSON payloads.
    """
    try:
        client = get_anon_client()

        source_payload = {
            "url": original_url,
            "source_type": "API_ANALYZE",
            "source": "POST /analyze",
        }
        client.table("url_sources").insert(source_payload).execute()

        scan_payload = {
            "url": original_url,
            "expiry_date": (datetime.now(timezone.utc) + timedelta(days=DEFAULT_SCAN_EXPIRY_DAYS)).isoformat(),
        }

        response = client.table("scans").insert(scan_payload).execute()
        if not response.data:
            raise HTTPException(status_code=500, detail="Failed to create analysis job")

        return {
            "message": "Analysis created",
            "url": {"original_url": original_url},
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
        scans = client.table("scans").select("*").execute().data or []

        total_scans = len(scans)

        return {
            "data": {
                "total_scans": total_scans,
            }
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch summary stats: {str(exc)}") from exc


@app.get("/stats/domains/{domain}")
def get_domain_stats(domain: str):
    raise HTTPException(
        status_code=410,
        detail="Domain stats are unavailable after removal of urls/url_id schema. Use /url-sources endpoints instead.",
    )
