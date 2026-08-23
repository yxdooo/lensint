# LENSINT REST API & STIX 2.1 Reference

LENSINT exposes a high-performance REST API powered by FastAPI for headless deployment, CI/CD pipelines, and automated DFIR / SOAR workflows.

---

## Starting the Server

```bash
lensint serve --host 0.0.0.0 --port 8000
```

---

## Endpoints

### 1. Healthcheck

- **Endpoint**: `GET /health`
- **Description**: Service health, framework version, and active configuration summary.
- **Example Response**:
```json
{
  "status": "healthy",
  "service": "lensint-api",
  "version": "2.5.0",
  "config": {
    "virustotal_configured": true,
    "max_upload_size_mb": 50,
    "cache_enabled": true
  }
}
```

---

### 2. Analyze Single Image (JSON)

- **Endpoint**: `POST /api/analyze`
- **Content-Type**: `multipart/form-data`
- **Query Parameters**:
  - `ela_quality` (int, default: 90): JPEG quality for ELA.
  - `geo_lookup` (bool, default: false): Perform reverse geocoding on GPS tags.
  - `generate_visuals` (bool, default: false): Include base64-encoded heatmap PNGs.
  - `use_cache` (bool, default: true): Query on-disk SHA-256 cache.
- **cURL Example**:
```bash
curl -X POST "http://localhost:8000/api/analyze?generate_visuals=true" \
     -F "file=@evidence.jpg"
```

---

### 3. Analyze Single Image (HTML Report)

- **Endpoint**: `POST /api/analyze/html`
- **Content-Type**: `multipart/form-data`
- **Response**: Standalone interactive HTML forensic report.
- **cURL Example**:
```bash
curl -X POST "http://localhost:8000/api/analyze/html" \
     -F "file=@evidence.jpg" -o report.html
```

---

### 4. Batch Multi-Image Analysis

- **Endpoint**: `POST /api/analyze/batch`
- **Content-Type**: `multipart/form-data`
- **Body**: Multiple `files` parts.
- **cURL Example**:
```bash
curl -X POST "http://localhost:8000/api/analyze/batch" \
     -F "files=@evidence1.jpg" \
     -F "files=@evidence2.png"
```

---

### 5. Forensic Cache Management

- `GET /api/cache/stats` — Inspect cache size, count, and oldest entry age.
- `DELETE /api/cache` — Clear all cached forensic results.
