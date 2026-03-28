from typing import Any
from datetime import datetime

from pydantic import BaseModel


class ScanCreate(BaseModel):
    url: str
    expiry_date: datetime
    openai_raw: dict[str, Any] | None = None
    vt_raw: dict[str, Any] | None = None


class ScanUpdate(BaseModel):
    url: str | None = None
    expiry_date: datetime | None = None
    openai_raw: dict[str, Any] | None = None
    vt_raw: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    error: str
    details: Any | None = None
