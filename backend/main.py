import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import httpx
import psycopg2
import vt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from config import settings, validate_settings
from schemas import ScanCreate, ScanUpdate
from supabase_client import get_anon_client

load_dotenv()

description = """
BigFish API
===========

A security-analysis orchestration service exposing individual endpoints for:

- **VirusTotal** – Scan and retrieve reputation data for URLs.
- **OpenAI** – Analyse scraped website content for phishing indicators.
- **TinyFish** – Automate browser-based tasks via SSE event streams.
- **Scans** – CRUD operations for scan records persisted in Supabase.
- **URL Sources** – Track where analysed URLs originated.
- **Analysis** – Full scan orchestration with database persistence.

Interactive docs are available at `/docs` (Swagger UI) and `/redoc` (ReDoc).
"""

tags_metadata = [
    {
        "name": "Health",
        "description": "Service health-check endpoints.",
    },
    {
        "name": "VirusTotal",
        "description": "Scan URLs and retrieve reputation data from VirusTotal.",
    },
    {
        "name": "OpenAI",
        "description": "Analyse scraped website content for phishing indicators using OpenAI.",
    },
    {
        "name": "TinyFish",
        "description": "Run browser-automation tasks via TinyFish with real-time SSE streaming.",
    },
    {
        "name": "Scans",
        "description": "CRUD operations for scan records in Supabase.",
    },
    {
        "name": "URL Sources",
        "description": "Track and query URL source records.",
    },
    {
        "name": "Analysis",
        "description": "Full scan orchestration with database persistence.",
    },
    {
        "name": "Stats",
        "description": "Summary statistics for scans.",
    },
]

app = FastAPI(
    title="BigFish API",
    summary="Individual endpoints for VirusTotal, OpenAI, TinyFish, and Supabase-backed scan persistence.",
    version="2.0.0",
    description=description,
    openapi_tags=tags_metadata,
    contact={
        "name": "BigFish Team",
        "url": "https://github.com/TinyFish-Hackathon-BigFish",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "https://tinyphish.vercel.app", "tinyphish-git-main-nickyseahs-projects.vercel.app", "tinyphish-1pjc90dao-nickyseahs-projects.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
# OpenAI (commented out — replaced with Gemini)
# OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
# OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
TINYFISH_API_KEY = os.getenv("TINYFISH_API_KEY")
TINYFISH_BROWSER_PROFILE = os.getenv("TINYFISH_BROWSER_PROFILE", "stealth")
TINYFISH_BASE_URL = "https://agent.tinyfish.ai"

# Database
DATABASE_URL = os.getenv("DATABASE_URL", settings.database_url)
DEFAULT_SCAN_EXPIRY_DAYS = 7


def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str = Field(
        ..., description="Health status of the service.", examples=["ok"]
    )


class VirusTotalRequest(BaseModel):
    url: str = Field(
        ...,
        description="URL to scan with VirusTotal.",
        examples=["https://example.com"],
    )


class VirusTotalResponse(BaseModel):
    url: str = Field(..., description="The URL that was scanned.")
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="VirusTotal scan results.",
    )


class OpenAIRequest(BaseModel):
    url: str = Field(
        ...,
        description="URL of the website being analysed.",
        examples=["https://suspicious-login.example.com"],
    )
    scraped_content: str = Field(
        ...,
        description="Scraped text content of the website (obtained from the /tinyfish endpoint).",
    )


class PhishingIndicator(BaseModel):
    category: str = Field(..., description="Category of the phishing indicator.")
    detail: str = Field(..., description="Explanation of what was found.")


class PhishingAnalysis(BaseModel):
    confidence_score: float = Field(
        ...,
        description="Phishing confidence score from 0.0 (safe) to 1.0 (definitely phishing).",
        ge=0.0,
        le=1.0,
    )
    is_phishing: bool = Field(
        ..., description="Whether the site is assessed as a phishing scam."
    )
    explanation: str = Field(
        ..., description="Detailed explanation of the phishing analysis."
    )
    indicators: list[PhishingIndicator] = Field(
        default_factory=list,
        description="List of specific phishing indicators detected.",
    )


class OpenAIResponse(BaseModel):
    url: str = Field(..., description="The URL that was analysed.")
    analysis: PhishingAnalysis = Field(
        ..., description="Phishing analysis results from OpenAI."
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw OpenAI response metadata.",
    )


class TinyFishRequest(BaseModel):
    url: str = Field(
        ...,
        description="URL to open in the TinyFish sandbox browser.",
        examples=["https://example.com"],
    )


# ---------------------------------------------------------------------------
# Phishing analysis system prompt
# ---------------------------------------------------------------------------
PHISHING_ANALYSIS_SYSTEM_PROMPT = """You are a cybersecurity expert specialising in phishing detection. You will be given the scraped text content of a website along with its URL. Your task is to analyse the content for phishing indicators and return a structured assessment.

Use the following guide of common phishing methods when performing your analysis:

## Common Phishing Indicators

### 1. URL / Domain Spoofing
- Typosquatting (e.g., "paypa1.com" instead of "paypal.com")
- Homoglyph attacks (using lookalike Unicode characters)
- Unusual TLDs for well-known brands (e.g., ".xyz", ".tk", ".gq")
- Excessively long or obfuscated URLs with many subdomains
- Use of IP addresses instead of domain names
- URL shorteners hiding the true destination

### 2. Urgency / Fear Tactics
- Claims that an account will be suspended, locked, or deleted
- Threats of legal action or financial penalty
- Fake security alerts ("Your account has been compromised!")
- Countdown timers or deadlines pressuring immediate action
- Statements like "Act now or lose access"

### 3. Credential Harvesting
- Login forms on pages that shouldn't require login
- Requests for passwords, PINs, social security numbers, or credit card details
- Forms asking for more information than necessary
- Fake "Verify your identity" or "Confirm your account" pages
- Mimicking well-known brand login pages (banks, email providers, social media)

### 4. Social Engineering Triggers
- Fake lottery wins, inheritance notices, or prize notifications
- Romantic or emotional appeals (romance scams)
- Fake job offers requiring personal information or payment
- Charity or disaster relief scams
- Impersonation of authority figures or executives

### 5. Technical Indicators in Page Content
- Grammatical errors, spelling mistakes, or awkward phrasing (especially for "official" pages)
- Low-quality or distorted logos and images
- Generic greetings ("Dear Customer" instead of using your name)
- Unusual sender addresses or reply-to addresses
- Links that don't match the displayed text (href mismatch)
- Use of free hosting services or generic CMS platforms
- Missing or invalid SSL certificates referenced in security claims
- Unusual page structure that doesn't match the claimed brand

### 6. Financial / Payment Red Flags
- Requests for payment via gift cards, wire transfers, or cryptocurrency
- Unsolicited refund or payment notifications
- Fake invoice or billing alerts
- Requests to update billing information via a link

### 7. Brand Impersonation
- Copying layout and design of legitimate websites
- Using official-looking but fake email addresses
- Referencing real company names, logos, or products deceptively
- Fake customer support phone numbers or chat widgets

### 8. Malware / Drive-by Download Indicators
- Prompts to download software, browser extensions, or "security updates"
- Fake antivirus scan results
- Automatic file downloads triggered on page load
- Requests to disable antivirus or firewall software

You MUST respond with valid JSON matching this exact schema:
{
    "confidence_score": <float between 0.0 and 1.0>,
    "is_phishing": <boolean>,
    "explanation": "<detailed string explaining your analysis>",
    "indicators": [
        {
            "category": "<one of: URL/Domain Spoofing, Urgency/Fear Tactics, Credential Harvesting, Social Engineering, Technical Indicators, Financial/Payment Red Flags, Brand Impersonation, Malware/Drive-by Downloads>",
            "detail": "<specific explanation of what was found>"
        }
    ]
}

Important rules:
- confidence_score: 0.0 means completely safe, 1.0 means definitely phishing. Use the full range.
- is_phishing: true if confidence_score >= 0.5, false otherwise.
- Only report indicators that you have evidence for in the provided content.
- If the content appears legitimate, report a low score with empty indicators and an explanation of why it appears safe.
- Do NOT wrap the JSON in markdown code fences. Return raw JSON only."""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get(
    "/health",
    tags=["Health"],
    summary="Health check",
    description="Returns a simple status payload to confirm the service is running.",
    response_model=HealthResponse,
)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post(
    "/virustotal",
    tags=["VirusTotal"],
    summary="Scan a URL with VirusTotal",
    description="Submit a URL for scanning via the VirusTotal API and return the report.",
    response_model=VirusTotalResponse,
)
async def virustotal(request: VirusTotalRequest) -> VirusTotalResponse:
    if not VIRUSTOTAL_API_KEY:
        return VirusTotalResponse(url=request.url, data={"error": "VIRUSTOTAL_API_KEY not set"})
    try:
        async with vt.Client(VIRUSTOTAL_API_KEY) as client:
            url_id = vt.url_id(request.url)
            # Try fetching an existing report first
            try:
                url_report = await client.get_object_async(f"/urls/{url_id}")
            except vt.error.APIError:
                # No existing report — submit for scanning and retry
                await client.scan_url_async(request.url)
                url_report = await client.get_object_async(f"/urls/{url_id}")
            return VirusTotalResponse(url=request.url, data=url_report.to_dict())
    except Exception as exc:
        return VirusTotalResponse(url=request.url, data={"error": str(exc)})


# ---------------------------------------------------------------------------
# Original OpenAI implementation (commented out — replaced with Gemini)
# ---------------------------------------------------------------------------
# @app.post(
#     "/openai",
#     tags=["OpenAI"],
#     summary="Analyse a website for phishing",
#     description=(
#         "Accept scraped website content and a URL. Use OpenAI to analyse the content "
#         "against common phishing indicators and return a confidence score, explanation, "
#         "and list of specific indicators detected."
#     ),
#     response_model=OpenAIResponse,
# )
# async def openai(request: OpenAIRequest) -> OpenAIResponse:
#     if not OPENAI_API_KEY:
#         return OpenAIResponse(
#             url=request.url,
#             analysis=PhishingAnalysis(
#                 confidence_score=0.0,
#                 is_phishing=False,
#                 explanation="OPENAI_API_KEY not configured.",
#                 indicators=[],
#             ),
#             data={"error": "OPENAI_API_KEY not set"},
#         )
#
#     user_message = (
#         f"URL: {request.url}\n\n"
#         f"Scraped website content:\n---\n{request.scraped_content}\n---"
#     )
#
#     payload: dict[str, Any] = {
#         "model": OPENAI_MODEL,
#         "instructions": PHISHING_ANALYSIS_SYSTEM_PROMPT,
#         "input": user_message,
#     }
#
#     try:
#         async with httpx.AsyncClient(timeout=60) as client:
#             resp = await client.post(
#                 "https://api.openai.com/v1/responses",
#                 json=payload,
#                 headers={
#                     "Authorization": f"Bearer {OPENAI_API_KEY}",
#                     "Content-Type": "application/json",
#                 },
#             )
#             resp.raise_for_status()
#             result = resp.json()
#     except httpx.HTTPStatusError as exc:
#         return OpenAIResponse(
#             url=request.url,
#             analysis=PhishingAnalysis(
#                 confidence_score=0.0,
#                 is_phishing=False,
#                 explanation=f"OpenAI API returned status {exc.response.status_code}.",
#                 indicators=[],
#             ),
#             data={"error": str(exc), "status_code": exc.response.status_code},
#         )
#     except httpx.RequestError as exc:
#         return OpenAIResponse(
#             url=request.url,
#             analysis=PhishingAnalysis(
#                 confidence_score=0.0,
#                 is_phishing=False,
#                 explanation="Failed to reach OpenAI API.",
#                 indicators=[],
#             ),
#             data={"error": str(exc)},
#         )
#
#     output_items = result.get("output", [])
#     raw_text = ""
#     for item in output_items:
#         if item.get("type") == "message":
#             for content_block in item.get("content", []):
#                 if content_block.get("type") == "output_text":
#                     raw_text += content_block.get("text", "")
#
#     if not raw_text:
#         raw_text = result.get("output_text", "")
#
#     try:
#         analysis_json = json.loads(raw_text)
#         analysis = PhishingAnalysis(**analysis_json)
#     except (json.JSONDecodeError, Exception) as exc:
#         return OpenAIResponse(
#             url=request.url,
#             analysis=PhishingAnalysis(
#                 confidence_score=0.0,
#                 is_phishing=False,
#                 explanation=f"Failed to parse OpenAI response: {exc}",
#                 indicators=[],
#             ),
#             data={"raw_response": raw_text, "parse_error": str(exc)},
#         )
#
#     return OpenAIResponse(
#         url=request.url,
#         analysis=analysis,
#         data={
#             "model": result.get("model", OPENAI_MODEL),
#             "id": result.get("id", ""),
#             "usage": result.get("usage", {}),
#         },
#     )


@app.post(
    "/openai",
    tags=["OpenAI"],
    summary="Analyse a website for phishing (powered by Gemini)",
    description=(
        "Accept scraped website content and a URL. Use Google Gemini to analyse "
        "the content against common phishing indicators and return a confidence "
        "score, explanation, and list of specific indicators detected."
    ),
    response_model=OpenAIResponse,
)
async def analyse_phishing(request: OpenAIRequest) -> OpenAIResponse:
    if not GEMINI_API_KEY:
        return OpenAIResponse(
            url=request.url,
            analysis=PhishingAnalysis(
                confidence_score=0.0,
                is_phishing=False,
                explanation="GEMINI_API_KEY not configured.",
                indicators=[],
            ),
            data={"error": "GEMINI_API_KEY not set"},
        )

    user_message = (
        f"URL: {request.url}\n\n"
        f"Scraped website content:\n---\n{request.scraped_content}\n---"
    )

    payload: dict[str, Any] = {
        "system_instruction": {"parts": [{"text": PHISHING_ANALYSIS_SYSTEM_PROMPT}]},
        "contents": [{"parts": [{"text": user_message}]}],
        "generationConfig": {"responseMimeType": "application/json"},
    }

    gemini_url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    )

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                gemini_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            result = resp.json()
    except httpx.HTTPStatusError as exc:
        return OpenAIResponse(
            url=request.url,
            analysis=PhishingAnalysis(
                confidence_score=0.0,
                is_phishing=False,
                explanation=f"Gemini API returned status {exc.response.status_code}.",
                indicators=[],
            ),
            data={"error": str(exc), "status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return OpenAIResponse(
            url=request.url,
            analysis=PhishingAnalysis(
                confidence_score=0.0,
                is_phishing=False,
                explanation="Failed to reach Gemini API.",
                indicators=[],
            ),
            data={"error": str(exc)},
        )

    # Extract text from Gemini response: candidates[0].content.parts[0].text
    raw_text = ""
    try:
        candidates = result.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            for part in parts:
                raw_text += part.get("text", "")
    except (IndexError, AttributeError):
        pass

    if not raw_text:
        return OpenAIResponse(
            url=request.url,
            analysis=PhishingAnalysis(
                confidence_score=0.0,
                is_phishing=False,
                explanation="Gemini returned an empty response.",
                indicators=[],
            ),
            data={"raw_response": result},
        )

    try:
        analysis_json = json.loads(raw_text)
        analysis = PhishingAnalysis(**analysis_json)
    except (json.JSONDecodeError, Exception) as exc:
        return OpenAIResponse(
            url=request.url,
            analysis=PhishingAnalysis(
                confidence_score=0.0,
                is_phishing=False,
                explanation=f"Failed to parse Gemini response: {exc}",
                indicators=[],
            ),
            data={"raw_response": raw_text, "parse_error": str(exc)},
        )

    return OpenAIResponse(
        url=request.url,
        analysis=analysis,
        data={
            "model": GEMINI_MODEL,
            "usage": result.get("usageMetadata", {}),
        },
    )


@app.post(
    "/tinyfish",
    tags=["TinyFish"],
    summary="Run a TinyFish sandbox scan via SSE streaming",
    description=(
        "Proxy the TinyFish SSE stream to the frontend so the UI can show "
        "live agent progress while the page is being scraped."
    ),
)
async def tinyfish(request: TinyFishRequest) -> StreamingResponse:
    if not TINYFISH_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="TINYFISH_API_KEY is not configured. Add it to your .env file.",
        )

    target_url = request.url
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    goal = (
        "Do the following:\n"
        "1. Extract and return ALL visible text content on the page.\n"
        "2. Note the final URL after any redirects.\n"
        "3. Report if any files were downloaded or if any download dialogs appeared.\n"
        "4. List any pop-ups, redirects to other domains, or suspicious behaviour.\n"
        "Return the results as structured data."
    )

    async def event_stream():
        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                async with client.stream(
                    "POST",
                    f"{TINYFISH_BASE_URL}/v1/automation/run-sse",
                    headers={
                        "X-API-Key": TINYFISH_API_KEY or "",
                        "Content-Type": "application/json",
                    },
                    json={
                        "url": target_url,
                        "goal": goal,
                        "browser_profile": TINYFISH_BROWSER_PROFILE,
                    },
                ) as response:
                    if response.status_code != 200:
                        error_body = await response.aread()
                        payload = json.dumps(
                            {
                                "type": "ERROR",
                                "message": f"TinyFish returned {response.status_code}: {error_body.decode()}",
                            }
                        )
                        yield f"data: {payload}\n\n"
                        return

                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            yield f"{line}\n\n"
                            # Close stream once COMPLETE arrives
                            try:
                                evt = json.loads(line[6:])
                                if evt.get("type") == "COMPLETE":
                                    return
                            except (json.JSONDecodeError, AttributeError):
                                pass

        except httpx.TimeoutException:
            payload = json.dumps(
                {
                    "type": "ERROR",
                    "message": "Request timed out after 180 s. The page may be too complex — try again.",
                }
            )
            yield f"data: {payload}\n\n"

        except Exception as exc:
            payload = json.dumps({"type": "ERROR", "message": str(exc)})
            yield f"data: {payload}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# Database health
# ---------------------------------------------------------------------------
@app.get(
    "/health/db",
    tags=["Health"],
    summary="Database health check",
    description="Checks that the database is reachable.",
)
def database_health_check() -> dict[str, str]:
    try:
        conn = get_db_connection()
        conn.close()
        return {"database": "connected"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(exc)}") from exc


# ---------------------------------------------------------------------------
# URL Sources
# ---------------------------------------------------------------------------
@app.get("/url-sources", tags=["URL Sources"], summary="List all URL sources")
def list_url_sources():
    try:
        client = get_anon_client()
        response = client.table("url_sources").select("*").order("created_at", desc=True).execute()
        return {"data": response.data}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch url sources: {str(exc)}") from exc


@app.get("/url-sources/by-url", tags=["URL Sources"], summary="Get URL sources by URL")
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


# ---------------------------------------------------------------------------
# Scans CRUD
# ---------------------------------------------------------------------------
@app.get("/scans", tags=["Scans"], summary="List all scans")
def list_scans():
    try:
        client = get_anon_client()
        response = client.table("scans").select("*").order("scanned_at", desc=True).execute()
        return {"data": response.data}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch scans: {str(exc)}") from exc


class SaveScanRequest(BaseModel):
    url: str = Field(..., description="The URL that was scanned.")
    source: str = Field(..., description="Where the user found the link (e.g. Email, SMS).")
    openai_raw: dict[str, Any] | None = Field(None, description="Full OpenAI/Gemini analysis result.")
    vt_raw: dict[str, Any] | None = Field(None, description="Full VirusTotal scan result.")


@app.post(
    "/scans/save",
    tags=["Scans"],
    summary="Save a completed scan result",
    description="Persists a full scan result (OpenAI + VirusTotal JSON) to Supabase and records the URL source.",
    status_code=status.HTTP_201_CREATED,
)
def save_scan_result(payload: SaveScanRequest):
    try:
        client = get_anon_client()

        # Record URL source
        source_payload = {
            "url": payload.url,
            "source_type": payload.source,
            "source": "TinyPhish Scan",
        }
        client.table("url_sources").insert(source_payload).execute()

        # Insert scan with raw payloads
        scan_payload: dict[str, Any] = {
            "url": payload.url,
            "expiry_date": (datetime.now(timezone.utc) + timedelta(days=DEFAULT_SCAN_EXPIRY_DAYS)).isoformat(),
            "openai_raw": payload.openai_raw,
            "vt_raw": payload.vt_raw,
        }

        response = client.table("scans").insert(scan_payload).execute()
        if not response.data:
            raise HTTPException(status_code=500, detail="Failed to save scan result")

        return {"data": response.data[0]}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save scan result: {str(exc)}") from exc


@app.get(
    "/scans/history",
    tags=["Scans"],
    summary="Get recent scan history",
    description="Returns the most recent scans with openai_raw and vt_raw for the history dropdown.",
)
def get_scan_history(limit: int = Query(20, ge=1, le=100, description="Max scans to return")):
    try:
        client = get_anon_client()
        response = (
            client.table("scans")
            .select("*")
            .order("scanned_at", desc=True)
            .limit(limit)
            .execute()
        )
        return {"data": response.data or []}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch scan history: {str(exc)}") from exc


@app.get("/scans/{scan_id}", tags=["Scans"], summary="Get a scan by ID")
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


@app.post("/scans", tags=["Scans"], summary="Create a new scan", status_code=status.HTTP_201_CREATED)
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


@app.patch("/scans/{scan_id}", tags=["Scans"], summary="Update a scan")
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


@app.delete("/scans/{scan_id}", tags=["Scans"], summary="Delete a scan")
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


# ---------------------------------------------------------------------------
# Analysis orchestration
# ---------------------------------------------------------------------------
@app.post(
    "/analyze",
    tags=["Analysis"],
    summary="Submit a URL for analysis",
    description=(
        "Records the input URL in url_sources, then creates a scan row. "
        "The scan can later be updated with OpenAI / VirusTotal payloads."
    ),
    status_code=status.HTTP_201_CREATED,
)
def analyze_url(original_url: str = Query(..., description="URL to analyze")):
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


@app.get(
    "/analyze/{scan_id}",
    tags=["Analysis"],
    summary="Get analysis result",
    description="Convenience endpoint for frontend polling.",
)
def get_analysis_result(scan_id: UUID):
    return get_scan_by_id(scan_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
@app.get("/stats/summary", tags=["Stats"], summary="Get summary statistics")
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


@app.get("/stats/domains/{domain}", tags=["Stats"], summary="Get domain stats (deprecated)")
def get_domain_stats(domain: str):
    raise HTTPException(
        status_code=410,
        detail="Domain stats are unavailable after removal of urls/url_id schema. Use /url-sources endpoints instead.",
    )
