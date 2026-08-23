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
| `--misp` | `PATH` | Export standardized MISP JSON Threat Event format |
| `--generate-yara` | `PATH` | Generate deployable YARA detection rule (.yar) matching detected threats and hashes |
| `--carve-memory` | `PATH` | Carve and analyze volatile image buffers from raw RAM memory dump (.raw, .dmp, .vmem) |
| `--watch-dir` | `DIR` | Run EDR real-time monitor on target directory for newly dropped evidence files |
| `--sandbox-dir` | `DIR` | Ingest and correlate dynamic sandbox run execution artifacts (CAPE / Cuckoo) |
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

### 1. Full Evidence Examination with HTML, MISP & YARA Export
```bash
lensint case_042_evidence.jpg \
  --case-id "CASE-2026-0042" \
  --examiner "Agent_Smith" \
  --html case_042_report.html \
  --json case_042_data.json \
  --misp case_042_misp.json \
  --generate-yara rule.yar \
  --geo-lookup
```

### 2. Memory Dump Image Carving
```bash
lensint --carve-memory /dumps/infected_host_memory.raw
```

### 3. Dynamic Malware Sandbox (CAPE/Cuckoo) Ingestion
```bash
lensint --sandbox-dir /opt/cuckoo/storage/analyses/1337/
```

### 4. Real-Time EDR File-Drop Directory Monitor
```bash
lensint --watch-dir /var/log/suricata/extracted_files/
```
