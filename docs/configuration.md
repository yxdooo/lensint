# LENSINT Configuration, Environment Variables, and Model Deployment

## Overview

LENSINT features a unified configuration subsystem (`lensint.config`) designed for zero-configuration standalone use, secure air-gapped forensic workstations, and containerized cloud/on-premise enterprise deployments.

---

## Configuration Loading Hierarchy

Configuration values are resolved at runtime in the following order of precedence (highest to lowest):
1. **Operating System Environment Variables**: Directly exported in shell or container environment.
2. **Current Working Directory `.env` File**: Loaded automatically from the active execution path (`./.env`).
3. **User Home Directory `.env` File**: Loaded from `~/.lensint/.env`.
4. **Built-in System Defaults**: Compiled dataclass default values.

---

## Environment Variables Reference

| Variable Name | Type | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `LENSINT_VIRUSTOTAL_API_KEY` | String | `None` | API key for VirusTotal file hash reputation queries |
| `LENSINT_SHODAN_API_KEY` | String | `None` | API key for Shodan infrastructure threat correlation |
| `LENSINT_ABUSEIPDB_API_KEY` | String | `None` | API key for AbuseIPDB IP reputation scoring |
| `LENSINT_API_KEY` | String | `None` | Secret key for REST API authentication (`X-API-Key` / `Bearer`). Leave empty for open local mode. |
| `LENSINT_MAX_UPLOAD_MB` | Integer | `50` | Maximum upload size threshold in Megabytes |
| `LENSINT_HOST` | String | `0.0.0.0` | Default network interface for REST API server |
| `LENSINT_PORT` | Integer | `8000` | Default TCP port for REST API server |
| `LENSINT_CORS_ORIGINS` | String | `http://localhost:8000,...` | Comma-delimited list of permitted CORS origins (or `*`) |
| `LENSINT_RATE_LIMIT_PER_MIN` | Integer | `30` | Maximum API requests per minute per client IP (active only when `LENSINT_API_KEY` is set) |
| `LENSINT_RATE_LIMIT_BURST` | Integer | `10` | Token-bucket burst tolerance above the per-minute rate |
| `LENSINT_CACHE_ENABLED` | Boolean | `true` | Enable on-disk SHA-256 result caching |
| `LENSINT_CACHE_TTL_HOURS` | Integer | `72` | Cache expiration window in hours |
| `LENSINT_CACHE_DIR` | Path | `~/.lensint/cache` | Directory path for forensic result cache store |
| `LENSINT_AUDIT_ENABLED` | Boolean | `true` | Enable ISO/IEC 27037 chained JSONL audit logging |
| `LENSINT_AUDIT_DIR` | Path | `~/.lensint/audit` | Directory path for sealed audit ledger logs |
| `LENSINT_LOG_LEVEL` | String | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `LENSINT_USER_AGENT` | String | `lensint-forensics-agent/3.5` | HTTP User-Agent string for Nominatim reverse geocoding |
| `LENSINT_GEOLOOKUP_TIMEOUT` | Integer | `3` | Timeout in seconds for reverse geocoding queries |
| `LENSINT_ONNX_MODEL_DIR` | Path | `~/.lensint/models` | Directory containing `deepfake_detector.onnx` and `manifest.json` |
| `LENSINT_MODULE_TIMEOUT` | Integer | `120` | Per-module analysis timeout in seconds. Modules exceeding this limit are skipped with a warning. |

---

## Setting Up Environment Configuration

Create a `.env` file in your working directory or copy from `.env.example`:

```bash
# Threat Intelligence Integrations
LENSINT_VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
LENSINT_SHODAN_API_KEY=your_shodan_api_key_here
LENSINT_ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# REST API Security
# Leave empty to run in open (unauthenticated) local mode
LENSINT_API_KEY=your_secure_server_token_here
LENSINT_MAX_UPLOAD_MB=50
LENSINT_CORS_ORIGINS=http://localhost:8000,http://127.0.0.1:8000

# Rate Limiting (active only when LENSINT_API_KEY is set)
LENSINT_RATE_LIMIT_PER_MIN=30
LENSINT_RATE_LIMIT_BURST=10

# Cache & Storage
LENSINT_CACHE_ENABLED=true
LENSINT_CACHE_TTL_HOURS=72
LENSINT_CACHE_DIR=~/.lensint/cache

# ISO/IEC 27037 Audit Trail
LENSINT_AUDIT_ENABLED=true
LENSINT_AUDIT_DIR=~/.lensint/audit
LENSINT_LOG_LEVEL=INFO

# Geocoding Service
LENSINT_USER_AGENT=lensint-forensics-agent/3.5
LENSINT_GEOLOOKUP_TIMEOUT=3

# Neural ONNX Deepfake Pipeline
# LENSINT_ONNX_MODEL_DIR=/path/to/models

# Per-module timeout (seconds); modules exceeding this are skipped with a WARNING log
LENSINT_MODULE_TIMEOUT=120
```

---

## ONNX Neural Model Deployment & Manifest Specification

LENSINT supports local neural deepfake and synthetic image detection using ONNX Runtime. To maintain strict forensic integrity and prevent model tampering or execution of unverified weights, every deployed model requires a cryptographic `manifest.json`.

### Model Directory Structure
```
~/.lensint/models/
├── deepfake_detector.onnx
└── manifest.json
```

### Manifest Schema Specification (`manifest.json`)
```json
{
  "model_name": "TruFor_SwinTransformer_Deepfake_V2",
  "model_version": "2.4.0",
  "model_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "input_tensor_name": "input_image",
  "input_size": [256, 256],
  "input_channels": 3,
  "input_mean": [0.485, 0.456, 0.406],
  "input_std": [0.229, 0.224, 0.225],
  "expected_classes": 2,
  "ai_class_index": 1,
  "output_activation": "softmax",
  "provenance": {
    "architecture": "Swin-B / High-Pass Feature Extractor",
    "training_datasets": ["FaceForensics++", "DiffusionForensics", "CASIA"],
    "license": "Research / Forensic Use"
  }
}
```

### Integrity Verification Workflow
When `NeuralDeepfakePipeline` initializes:
1. It computes the SHA-256 hash of `deepfake_detector.onnx`.
2. It compares the computed hash with `model_sha256` defined in `manifest.json`.
3. If the hash does not match, execution is halted with `ValueError: Model integrity verification failed`, preventing adversarial model substitution.
4. Input image tensors are normalized and mapped dynamically based on manifest dimensions, means, and standard deviations.

### Model Setup CLI Workflow

The `model_manager` module provides CLI commands for diagnosing and configuring the neural pipeline without writing JSON manually:

```bash
# 1. Check current model pipeline status
lensint model-info

# 2. Generate a manifest.json skeleton (pre-fills SHA-256 if the .onnx file already exists)
lensint model-setup

# 3. Generate skeleton at a custom path
lensint model-setup /opt/lensint/models/manifest.json
```

If `manifest.json` or `deepfake_detector.onnx` is missing, `lensint model-info` outputs a structured diagnostic:

```
✗ Neural ONNX Pipeline — NOT AVAILABLE
• ONNX model file not found: /home/user/.lensint/models/deepfake_detector.onnx
  -> Place your deepfake_detector.onnx file in that directory,
     or set LENSINT_ONNX_MODEL_DIR env var to the parent directory.

Run lensint model-setup to generate a manifest skeleton in the model directory.
```

---

## Rate Limiting Configuration

When `LENSINT_API_KEY` is configured, the REST API enforces a **token-bucket rate limiter** per client IP. The rate limiter has no external dependencies and is implemented entirely in-process.

| Parameter | Default | Environment Variable |
| :--- | :--- | :--- |
| Requests per minute | `30` | `LENSINT_RATE_LIMIT_PER_MIN` |
| Burst tolerance | `10` | `LENSINT_RATE_LIMIT_BURST` |

Throttled requests receive HTTP `429 Too Many Requests` with the following response headers:

| Header | Description |
| :--- | :--- |
| `Retry-After` | Seconds until the client may retry |
| `X-RateLimit-Limit` | Configured requests per minute |
| `X-RateLimit-Remaining` | Remaining tokens in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the bucket refills |

Rate limiting is **automatically disabled** when `LENSINT_API_KEY` is not set, preserving unrestricted local development usage.


## Production Docker Deployment

Deploy LENSINT in enterprise environments using containerized microservices:

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgl1 \
    libglib2.0-0 \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -e ".[all]"

EXPOSE 8000

ENV LENSINT_HOST=0.0.0.0
ENV LENSINT_PORT=8000

CMD ["lensint", "serve"]
```
