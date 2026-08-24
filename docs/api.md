# LENSINT REST API & Automated Ingestion Specification

## Overview

The LENSINT REST API is an asynchronous, high-throughput media forensics interface built on FastAPI and Uvicorn. Designed for automated Security Operations Center (SOC) pipelines, Security Orchestration, Automation, and Response (SOAR) workflows, and Digital Forensics and Incident Response (DFIR) ingestion systems, the API exposes endpoints for deep forensic analysis, PDF courtroom report generation, batch processing, and cryptographic cache management.

---

## Server Deployment

Start the API service using the LENSINT CLI:

```bash
lensint serve --host 0.0.0.0 --port 8000
```

Alternatively, deploy using standard ASGI servers:

```bash
uvicorn lensint.server:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## Authentication and Security Architecture

### 1. API Key Authentication
When the `LENSINT_API_KEY` environment variable is defined, all mutating and analytical endpoints require valid authentication credentials. The API accepts tokens via either of two HTTP headers:

- `X-API-Key: <TOKEN>`
- `Authorization: Bearer <TOKEN>`

Requests lacking valid credentials return HTTP `401 Unauthorized`. If `LENSINT_API_KEY` is not set, the API operates in unauthenticated mode for local air-gapped environments.

### 2. Streaming Upload Protection and Memory Isolation
To prevent Denial of Service (DoS) attacks via memory exhaustion and large disk write floods, all uploads are streamed through fixed 64 KB buffers with active byte counters. If an upload exceeds `LENSINT_MAX_UPLOAD_MB` (default: 50 MB), the stream is terminated immediately, returning HTTP `413 Payload Too Large`, and temporary files are unlinked.

### 3. Cross-Origin Resource Sharing (CORS)
CORS policies are controlled via the `LENSINT_CORS_ORIGINS` environment variable (comma-delimited list of authorized origins). By default, local loopback origins (`http://localhost:8000`, `http://127.0.0.1:8000`, `http://localhost:3000`) are permitted.

---

## Endpoint Reference

### 1. Health and Configuration Status
- **Method**: `GET`
- **Route**: `/health`
- **Authentication**: None required.
- **Description**: Returns operational status, framework version, authentication state, CORS configuration, and active subsystem parameters.

#### Response Example (HTTP 200)
```json
{
  "status": "healthy",
  "service": "lensint-api",
  "version": "3.6.0",
  "auth_enabled": true,
  "cors_origins": ["http://localhost:8000", "http://127.0.0.1:8000"],
  "config": {
    "virustotal_configured": true,
    "shodan_configured": false,
    "abuseipdb_configured": false,
    "max_upload_size_mb": 50,
    "server_host": "0.0.0.0",
    "server_port": 8000,
    "cache_enabled": true,
    "cache_ttl_hours": 72,
    "audit_log_enabled": true,
    "log_level": "INFO"
  }
}
```

---

### 2. Single Media Analysis (JSON)
- **Method**: `POST`
- **Route**: `/api/analyze`
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `file` (Binary, required): The target image or video evidence file.
  - `ela_quality` (Integer, query, default: `90`, range: `1-100`): JPEG recompression quality for Error Level Analysis.
  - `geo_lookup` (Boolean, query, default: `false`): Perform reverse geocoding via OpenStreetMap Nominatim if GPS tags exist.
  - `generate_visuals` (Boolean, query, default: `false`): Include base64-encoded visual artifact images (ELA maps, cloning overlays).
  - `use_cache` (Boolean, query, default: `true`): Check on-disk SHA-256 result cache before running analysis.
- **Headers**:
  - `X-API-Key` or `Authorization: Bearer <TOKEN>` (if auth is enabled).

#### cURL Request Example
```bash
curl -X POST "http://localhost:8000/api/analyze?ela_quality=90&geo_lookup=true&generate_visuals=false&use_cache=true" \
     -H "X-API-Key: YOUR_API_KEY" \
     -F "file=@evidence_item.jpg"
```

#### Response Structure (HTTP 200)
```json
{
  "target_path": "/tmp/tmp_upload_8372.jpg",
  "timestamp": "2026-08-24 00:22:15 UTC",
  "overall_risk_score": 92.5,
  "overall_risk_level": "CRITICAL",
  "summary_findings": [
    "Hidden trailing payload (4520 bytes) found appended past image EOF.",
    "YARA Rule match confirmed threat: WebShell_Generic_PHP_Eval.",
    "Bayesian Fusion Engine escalated risk to CRITICAL (Risk: 92.5/100.0)."
  ],
  "analysis_duration_seconds": 0.42,
  "cache_hit": false,
  "integrity": {
    "file_name": "evidence_item.jpg",
    "file_size_bytes": 1048576,
    "detected_format": "JPEG",
    "detected_mime": "image/jpeg",
    "md5": "c4ca4238a0b923820dcc509a6f75849b",
    "sha1": "356a192b7913b04c54574d18c28d46e6395428ab",
    "sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "sha512": "36f56388221257b774b171449bdd01b205570d8fbf19ebb9d1000826b2a408b8b5564fb3b38914d19f73429db152c90f00b932239c4f31f8a4fb356ca0ec9e0e",
    "is_screenshot": false,
    "extension_mismatch": false,
    "is_corrupt_or_truncated": false
  },
  "tampering": {
    "ela_suspicion_score": 78.4,
    "copy_move_detected": true,
    "copy_move_match_count": 14,
    "jpeg_ghosts_detected": true,
    "dqt_hardware_mismatch": true,
    "dqt_identified_encoder": "Adobe Photoshop 2024",
    "cfa_tampering_detected": true,
    "cfa_inconsistency_score": 64.2,
    "block_grid_shifted": false,
    "suspicion_level": "HIGH"
  },
  "stego": {
    "has_overlay_data": true,
    "overlay_size_bytes": 4520,
    "lsb_stego_detected": true,
    "rs_steganalysis_detected": true,
    "rs_estimated_embedding_rate": 0.38,
    "c2_stego_detected": true,
    "dct_stego_detected": true,
    "jsteg_payload_detected": true
  },
  "prnu": {
    "fingerprint_extracted": true,
    "noise_residual_energy": 1.042,
    "is_device_matched": false,
    "peak_to_correlation_energy": 12.4,
    "false_alarm_rate_estimate": 0.042
  },
  "pdq": {
    "pdq_hash_hex": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
    "quality_score": 94,
    "is_threat_match": false,
    "min_hamming_distance": 256
  },
  "timestamp_token": {
    "status": "GRANTED",
    "timestamp_utc": "2026-08-24T00:22:15.120450+00:00",
    "tsa_server": "https://freetsa.org/tsr",
    "is_trusted_tsa": true,
    "serial_number": "4f9a2c8e1b7d3a50"
  },
  "fusion_telemetry": {
    "prior_probability": 0.1,
    "posterior_probability": 0.925,
    "calibrated_score": 92.5,
    "initial_log_odds": -2.197,
    "final_log_odds": 2.513,
    "contributing_indicators": {
      "ela_disparity": 1.482,
      "copy_move_cloning": 4.221,
      "c2_stego_signature": 2.833,
      "confirmed_malicious_payload": 6.5
    },
    "correlation_groups_activated": [
      "jpeg_compression_artifacts",
      "spatial_cloning",
      "steganography_lsb"
    ]
  }
}
```

---

### 3. Courtroom Expert Witness PDF Report Generation
- **Method**: `POST`
- **Route**: `/api/analyze/pdf`
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `file` (Binary, required): Target evidence item.
  - `case_id` (String, query, default: `"CASE-2026-DFIR-001"`): Case identifier recorded in the custody ledger.
  - `examiner` (String, query, default: `"Senior Digital Forensic Examiner"`): Official examiner credentials.
  - `ela_quality` (Integer, query, default: `90`).
  - `use_cache` (Boolean, query, default: `true`).
- **Response**: Streams binary `application/pdf` with `Content-Disposition: attachment; filename="Expert_Forensic_Report_<HASH>.pdf"`. Temporary server files are cleaned automatically after response completion via background tasks.

#### cURL Request Example
```bash
curl -X POST "http://localhost:8000/api/analyze/pdf?case_id=CASE-2026-CRIM-9912&examiner=Dr.+Alice+Vance" \
     -H "X-API-Key: YOUR_API_KEY" \
     -F "file=@evidence.jpg" \
     --output "Courtroom_Expert_Report.pdf"
```

---

### 4. Interactive Dark-Mode HTML Report Generation
- **Method**: `POST`
- **Route**: `/api/analyze/html`
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `file` (Binary, required).
  - `ela_quality` (Integer, query, default: `90`).
  - `geo_lookup` (Boolean, query, default: `true`).
  - `generate_visuals` (Boolean, query, default: `true`).
  - `use_cache` (Boolean, query, default: `true`).
- **Response**: Standalone, single-file HTML document containing embedded base64 heatmaps, interactive charts, and evidence tables.

#### cURL Request Example
```bash
curl -X POST "http://localhost:8000/api/analyze/html" \
     -H "X-API-Key: YOUR_API_KEY" \
     -F "file=@evidence.jpg" \
     --output "forensic_report.html"
```

---

### 5. Concurrent Batch Analysis
- **Method**: `POST`
- **Route**: `/api/analyze/batch`
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `files` (Multiple binary parts, required): Array of files to process.
  - Query parameters matching single-file analysis.
- **Response**: Aggregated JSON array containing individual analysis objects or localized error objects for corrupted items.

#### cURL Request Example
```bash
curl -X POST "http://localhost:8000/api/analyze/batch" \
     -H "X-API-Key: YOUR_API_KEY" \
     -F "files=@evidence_01.jpg" \
     -F "files=@evidence_02.png" \
     -F "files=@evidence_03.mp4"
```

---

### 6. Forensic Cache Management
- **`GET /api/cache/stats`**: Returns cache utilization metrics.
- **`DELETE /api/cache`**: Flushes all cached results from disk.

#### cURL Request Examples
```bash
# Check cache statistics
curl -X GET "http://localhost:8000/api/cache/stats"

# Flush cache entries
curl -X DELETE "http://localhost:8000/api/cache" \
     -H "X-API-Key: YOUR_API_KEY"
```

---

## Automation & Integration Scripting

### Python `requests` Client Example

```python
import os
import requests

API_URL = "http://127.0.0.1:8000"
API_KEY = os.getenv("LENSINT_API_KEY", "")
HEADERS = {"X-API-Key": API_KEY} if API_KEY else {}


def analyze_evidence(image_path: str) -> dict:
    """Submit digital evidence file to LENSINT REST API for forensic analysis."""
    url = f"{API_URL}/api/analyze"
    params = {
        "ela_quality": 90,
        "geo_lookup": True,
        "generate_visuals": False,
        "use_cache": True,
    }

    with open(image_path, "rb") as f:
        files = {"file": (os.path.basename(image_path), f, "application/octet-stream")}
        response = requests.post(url, headers=HEADERS, params=params, files=files, timeout=30.0)

    response.raise_for_status()
    return response.json()


def download_courtroom_pdf(image_path: str, output_pdf: str, case_id: str, examiner: str) -> None:
    """Request and save an official FRE 702 Expert Witness PDF report."""
    url = f"{API_URL}/api/analyze/pdf"
    params = {
        "case_id": case_id,
        "examiner": examiner,
        "use_cache": True,
    }

    with open(image_path, "rb") as f:
        files = {"file": (os.path.basename(image_path), f, "application/octet-stream")}
        response = requests.post(url, headers=HEADERS, params=params, files=files, stream=True, timeout=60.0)

    response.raise_for_status()
    with open(output_pdf, "wb") as out_f:
        for chunk in response.iter_content(chunk_size=65536):
            out_f.write(chunk)


if __name__ == "__main__":
    result = analyze_evidence("sample_evidence.jpg")
    print(f"Overall Risk Verdict: {result['overall_risk_level']} (Score: {result['overall_risk_score']})")
    print(f"RFC 3161 TSA Timestamp: {result['timestamp_token']['timestamp_utc']}")
    
    download_courtroom_pdf(
        image_path="sample_evidence.jpg",
        output_pdf="Courtroom_Report_CASE-991.pdf",
        case_id="CASE-2026-CRIM-991",
        examiner="Special Agent Vance",
    )
    print("Courtroom PDF downloaded successfully.")
```
