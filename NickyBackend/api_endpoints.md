# URL Analysis API - Endpoints Documentation

## Health Endpoints

### GET /health
Returns basic service health status.

### GET /health/db
Checks database connectivity.

---

## URL Endpoints

### GET /urls
Removed after schema migration.

### GET /urls/{url_id}
Removed after schema migration.

### GET /urls/by-original?original_url=...
Removed after schema migration.

### POST /urls
Removed after schema migration.

### PATCH /urls/{url_id}
Removed after schema migration.

### DELETE /urls/{url_id}
Removed after schema migration.

### GET /urls/{url_id}/scans
Removed after schema migration.

---

## URL Sources Endpoints

### GET /url-sources
Retrieve all rows from the `url_sources` table.

### GET /url-sources/by-url?url=...
Retrieve rows from `url_sources` where `url` exactly matches the provided URL.

---

## Scan Endpoints

### GET /scans
Retrieve all scans.

### GET /scans/{scan_id}
Retrieve a specific scan by ID.

### POST /scans
Create a new scan manually.
- Required fields: `url`, `expiry_date`
- Optional fields: `openai_raw`, `vt_raw`

### PATCH /scans/{scan_id}
Update scan results (e.g. openai_raw, vt_raw, expiry_date).

### DELETE /scans/{scan_id}
Delete a scan.

---

## Analysis Endpoints (Core Flow)

### POST /analyze
Submit a URL for analysis.
- Stores the URL in `url_sources`
- Creates a scan row with required fields
- Automatically sets `scan.url` to the submitted URL
- Automatically sets `scan.expiry_date` to current UTC time + 7 days

### GET /analyze/{scan_id}
Retrieve analysis result (used for polling).

---

## Statistics Endpoints

### GET /stats/summary
Returns overall statistics:
- Total scans

### GET /stats/domains/{domain}
Returns `410 Gone` because domain-based scan stats depended on the dropped `urls` table.

---

## Notes

- URLs are stored in `url_sources` (not guaranteed unique).
- Scans are now independent rows (no `url_id` foreign key).
- External services (Tinyfish, VirusTotal) update scan results asynchronously.
