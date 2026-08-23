# LENSINT Command Line Interface (CLI) Guide

## Synopsis

```bash
lensint [TARGET] [OPTIONS]
lensint serve [--host HOST] [--port PORT]
```

---

## Command Line Arguments

| Option | Argument | Description |
| :--- | :--- | :--- |
| `-v`, `--version` | None | Display LENSINT version string and exit |
| `--html` | `PATH` | Export standalone interactive HTML report |
| `--json` | `PATH` | Export machine-readable JSON forensic findings |
| `--stix` | `PATH` | Export standardized STIX 2.1 Threat Intelligence Bundle |
| `--extract-overlay` | `PATH` | Extract trailing binary payload appended past image EOF |
| `--geo-lookup` | None | Reverse geocode EXIF GPS tags into physical street address |
| `--batch` | None | Recursively process all supported images in target directory |
| `--no-cache` | None | Bypass on-disk SHA-256 result cache and re-analyze |
| `--case-id` | `ID` | Case Identifier recorded in cryptographically sealed audit ledger |
| `--examiner` | `NAME` | Name of forensic analyst recorded in chain of custody |
| `--audit-log` | `PATH` | Custom path to save sealed audit log entry |
| `--no-audit` | None | Suppress chain of custody audit trail recording |
| `-q`, `--quiet` | None | Output only the final forensic verdict without detailed tables |

---

## Practical Examples

### 1. Full Evidence Examination with HTML & JSON Export
```bash
lensint case_042_evidence.jpg \
  --case-id "CASE-2026-0042" \
  --examiner "Agent_Smith" \
  --html case_042_report.html \
  --json case_042_data.json \
  --geo-lookup
```

### 2. Threat Hunting & STIX 2.1 Bundle Generation
```bash
lensint malicious_carrier.png \
  --stix threat_intel_bundle.json \
  --extract-overlay extracted_payload.bin
```

### 3. High-Throughput Directory Batch Processing
```bash
lensint /evidence/seized_devices/folder_a/ \
  --batch \
  --html batch_report.html \
  --json batch_summary.json \
  --quiet
```
