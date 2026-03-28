from typing import Any, Literal

from pydantic import BaseModel


class UrlCreate(BaseModel):
    original_url: str
    domain: str | None = None


class UrlUpdate(BaseModel):
    original_url: str | None = None
    domain: str | None = None


class ScanCreate(BaseModel):
    url_id: str
    user_id: str | None = None
    tinyfish_verdict: str | None = None
    tinyfish_raw: dict[str, Any] | None = None
    vt_verdict: str | None = None
    vt_malicious_votes: int = 0
    vt_total_votes: int = 0
    vt_raw: dict[str, Any] | None = None
    final_verdict: Literal["SAFE", "SUSPICIOUS", "MALICIOUS", "PENDING", "ERROR"] = "PENDING"
    risk_score: int | None = None


class ScanUpdate(BaseModel):
    tinyfish_verdict: str | None = None
    tinyfish_raw: dict[str, Any] | None = None
    vt_verdict: str | None = None
    vt_malicious_votes: int | None = None
    vt_total_votes: int | None = None
    vt_raw: dict[str, Any] | None = None
    final_verdict: Literal["SAFE", "SUSPICIOUS", "MALICIOUS", "PENDING", "ERROR"] | None = None
    risk_score: int | None = None


class ErrorResponse(BaseModel):
    error: str
    details: Any | None = None
