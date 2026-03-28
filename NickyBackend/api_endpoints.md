# URL Analysis API - Endpoints Documentation

## Health Endpoints

### GET /health
Returns basic service health status.

### GET /health/db
Checks database connectivity.

---

## URL Endpoints

### GET /urls
Retrieve all stored URLs.

### GET /urls/{url_id}
Retrieve a specific URL by its ID.

### GET /urls/by-original?original_url=...
Retrieve a URL using its original URL string.

### POST /urls
Create a new URL record.

### PATCH /urls/{url_id}
Update an existing URL.

### DELETE /urls/{url_id}
Delete a URL.

### GET /urls/{url_id}/scans
Retrieve all scans associated with a specific URL.

---

## Scan Endpoints

### GET /scans
Retrieve all scans.

### GET /scans/{scan_id}
Retrieve a specific scan by ID.

### POST /scans
Create a new scan manually.

### PATCH /scans/{scan_id}
Update scan results (e.g. verdict, risk score).

### DELETE /scans/{scan_id}
Delete a scan.

---

## Analysis Endpoints (Core Flow)

### POST /analyze
Submit a URL for analysis.
- Creates URL if not exists
- Creates a scan with PENDING status

### GET /analyze/{scan_id}
Retrieve analysis result (used for polling).

---

## Statistics Endpoints

### GET /stats/summary
Returns overall statistics:
- Total scans
- Verdict breakdown (safe, malicious, etc.)
- Average risk score

### GET /stats/domains/{domain}
Returns statistics for a specific domain:
- Total scans
- Verdict breakdown

---

## Notes

- URLs are stored uniquely.
- Each URL can have multiple scans.
- External services (Tinyfish, VirusTotal) update scan results asynchronously.
- Risk score must be between 0–100.
