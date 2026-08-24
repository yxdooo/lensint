# LENSINT Command Line Interface (CLI) User Manual & Operational Workflows

## Synopsis

```bash
lensint [TARGET] [OPTIONS]
lensint serve [--host HOST] [--port PORT]
```

LENSINT provides an operator-grade Command Line Interface (CLI) designed for incident responders, law enforcement forensic analysts, and automated DFIR scripting. The CLI supports single-target forensic examination, multi-threaded batch ingestion, volatile memory dump carving, dynamic sandbox artifact ingestion, and real-time directory monitoring.

---

## Command Line Arguments Reference

| Option | Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `target` | `PATH` | Positional | `None` | Path to target media file or directory for batch analysis |
| `-v`, `--version` | None | Flag | `False` | Output framework version string and exit |
| `--pdf`, `--pdf-report` | `PATH` | String | `None` | Generate an official courtroom-grade Expert Witness PDF report (ISO/IEC 27037 compliant) |
| `--html` | `PATH` | String | `None` | Export standalone interactive dark-mode HTML forensic report |
| `--json` | `PATH` | String | `None` | Export comprehensive machine-readable JSON forensic data |
| `--stix` | `PATH` | String | `None` | Export standardized STIX 2.1 Threat Intelligence Bundle |
| `--misp` | `PATH` | String | `None` | Export standardized MISP JSON Threat Event |
| `--generate-yara` | `PATH` | String | `None` | Generate deployable YARA detection rule (`.yar`) matching detected threats and hashes |
| `--extract-overlay` | `PATH` | String | `None` | Extract binary payload appended past image/video EOF container boundary |
| `--carve-memory` | `PATH` | String | `None` | Carve and analyze volatile image buffers from raw RAM dump (`.raw`, `.dmp`, `.vmem`) |
| `--out-dir` | `DIR` | String | `None` | Directory path to save carved memory images or batch artifacts |
| `--watch-dir` | `DIR` | String | `None` | Run real-time filesystem watcher on directory for newly dropped files |
| `--sandbox-dir` | `DIR` | String | `None` | Ingest and correlate dynamic sandbox run execution artifacts (CAPE / Cuckoo) |
| `--tsa-server` | `URL` | String | `None` | RFC 3161 Time-Stamp Authority endpoint for digital timestamping |
| `--case-id` | `ID` | String | `None` | Forensic Case Identifier recorded in cryptographically sealed audit ledger |
| `--examiner` | `NAME` | String | `None` | Name of forensic examiner recorded in chain of custody |
| `--audit-log` | `PATH` | String | `None` | Custom path to append cryptographically sealed forensic audit log entry |
| `--no-audit` | None | Flag | `False` | Disable forensic audit trail recording for this execution |
| `--geo-lookup` | None | Flag | `False` | Reverse geocode EXIF GPS coordinates into physical address via OpenStreetMap |
| `--ela-quality` | `INT` | Integer | `90` | JPEG recompression quality for Error Level Analysis (`1-100`) |
| `--min-string-len`| `INT` | Integer | `4` | Minimum character length for ASCII and UTF-16LE string extraction |
| `--no-cache` | None | Flag | `False` | Bypass on-disk SHA-256 result cache and force complete re-analysis |
| `--no-visuals` | None | Flag | `False` | Disable generation of visual ELA/thumbnails for maximum processing throughput |
| `--batch` | None | Flag | `False` | Force recursive processing of all supported media files within target directory |
| `-q`, `--quiet` | None | Flag | `False` | Suppress detailed console tables and output only final forensic verdict |

---

## Operational Scenarios

### Scenario 1: Formal Courtroom Evidence Examination (ISO/IEC 27037 & RFC 3161)
Conducts a full forensic examination on seized photographic evidence, queries a public RFC 3161 Time-Stamp Authority for non-repudiation, records the examiner identity in the chained audit ledger, and outputs a courtroom-admissible PDF report alongside interactive HTML and raw JSON datasets.

```bash
lensint evidence_item_042.jpg \
  --case-id "CASE-2026-CRIM-9912" \
  --examiner "Dr. Jane Doe, Ph.D." \
  --tsa-server "https://freetsa.org/tsr" \
  --pdf-report "Courtroom_Expert_Report.pdf" \
  --html "interactive_report.html" \
  --json "forensic_data.json" \
  --geo-lookup
```

### Scenario 2: Steganographic Payload Carving and Automated YARA Rule Generation
Analyzes a suspected C2 steganographic carrier, extracts trailing binary payloads appended past the image EOF, and automatically generates a deployable YARA rule matching the carrier hash, file magic, and extracted payload signatures for immediate enterprise endpoint deployment.

```bash
lensint suspected_carrier.png \
  --extract-overlay "extracted_payload.bin" \
  --generate-yara "stego_detection_rule.yar" \
  --stix "stego_threat_bundle.json" \
  --misp "misp_event.json"
```

### Scenario 3: Volatile Memory Dump Image Carving (`--carve-memory`)
Scans unallocated RAM, process heaps, and virtual address descriptors (VADs) within physical memory dumps (`.raw`, `.dmp`, `.vmem`) to recover uncommitted GDI/DIB graphic surfaces, browser cache images, and in-memory C2 steganography carrier buffers.

```bash
lensint --carve-memory /dumps/infected_workstation_ram.raw \
        --out-dir /cases/case_9912/carved_images/
```

### Scenario 4: Dynamic Malware Sandbox Artifact Ingestion (`--sandbox-dir`)
Ingests automated malware execution runs from CAPE or Cuckoo sandbox storage directories. Automatically parses process trees, extracts runtime desktop screenshots, scans OCR visual surfaces for leaked API keys or credentials, and correlates network indicators into a consolidated threat verdict.

```bash
lensint --sandbox-dir /opt/cuckoo/storage/analyses/1337/ \
        --html /reports/sandbox_run_1337_report.html
```

### Scenario 5: Real-Time EDR File-Drop Directory Monitoring (`--watch-dir`)
Runs a continuous, low-latency filesystem monitor on network share drop-zones or Suricata extracted file directories. Audits incoming media files as they are written to disk, emitting high-priority console alerts when CRITICAL or HIGH risk scores are detected.

```bash
lensint --watch-dir /var/log/suricata/extracted_files/
```

### Scenario 6: High-Throughput Batch Processing
Recursively scans large directories containing thousands of images. Analysis is distributed across a worker pool with thread-safe result emission. When outputting reports in batch mode, files are automatically suffixed with the target stem and hash prefix (`<base>_<stem>_<hash6>.<ext>`) to prevent collision.

```bash
lensint /evidence/batch_intake/ \
  --batch \
  --no-visuals \
  --html /reports/batch_report.html \
  --json /reports/batch_data.json \
  --quiet
```

### Scenario 7: Headless REST API and Web UI Daemon
Launches the asynchronous REST API server with embedded Swagger documentation and interactive drag-and-drop web UI.

```bash
lensint serve --host 0.0.0.0 --port 8000
```
