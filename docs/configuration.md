# LENSINT Configuration Guide

LENSINT uses a unified configuration engine (`lensint/config.py`) that reads settings from environment variables and `.env` files.

---

## Configuration Variables

| Variable Name | Default Value | Description |
| :--- | :--- | :--- |
| `LENSINT_VIRUSTOTAL_API_KEY` | `None` | VirusTotal API key for automated file hash reputation lookups |
| `LENSINT_SHODAN_API_KEY` | `None` | Shodan API key for host infrastructure intelligence |
| `LENSINT_ABUSEIPDB_API_KEY` | `None` | AbuseIPDB API key for IP reputation scoring |
| `LENSINT_MAX_UPLOAD_MB` | `50` | Maximum upload size limit in Megabytes for API & Web UI |
| `LENSINT_CACHE_ENABLED` | `true` | Enable SHA-256 based on-disk result caching |
| `LENSINT_CACHE_TTL_HOURS` | `72` | Cache expiration time window in hours |
| `LENSINT_CACHE_DIR` | `~/.lensint/cache` | Custom directory path for forensic result cache |
| `LENSINT_AUDIT_ENABLED` | `true` | Enable cryptographically sealed chain of custody logging |
| `LENSINT_AUDIT_DIR` | `~/.lensint/audit` | Custom directory path for JSONL audit ledgers |
| `LENSINT_LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `LENSINT_USER_AGENT` | `lensint-forensics/2.5` | User Agent string for OpenStreetMap geocoding |
| `LENSINT_GEOLOOKUP_TIMEOUT` | `3` | Timeout in seconds for Nominatim reverse geocoding |

---

## Setting Up Environment Configuration

Create a `.env` file in the root of your project:

```bash
cp .env.example .env
```
