# Lensint v3.5 Enterprise

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688.svg)](https://fastapi.tiangolo.com/)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1%20Ready-green.svg)](https://oasis-open.github.io/cti-documentation/)
[![MISP](https://img.shields.io/badge/MISP-Event%20Ready-red.svg)](https://www.misp-project.org/)
[![YARA](https://img.shields.io/badge/YARA-Auto%20Generator-orange.svg)](https://virustotal.github.io/yara/)
[![Tests](https://img.shields.io/badge/tests-73%20passed-brightgreen.svg)](https://github.com/yxdooo/lensint/actions)

LENSINT is an advanced digital image forensics and threat hunting framework built for incident response, threat intelligence, and artifact analysis. It provides multi-dimensional inspection by combining classical physical image tampering analysis with steganography decoding, anomaly detection, neural model inference, and credential scanning.

> **Transparency Notice:** LENSINT's stego extractors (F5, OutGuess, JSteg) operate at the JPEG byte-stream level, not the true DCT coefficient domain. They are useful for heuristic detection and carrier identification — not guaranteed cross-tool interoperability decoding. See inline docstrings for the full scope of each algorithm.

---

## Key Capabilities

### 1. Memory Forensics (`--carve-memory`)
- **Volatile RAM Dump Carver**: Carves image buffers (`PNG`, `JPEG`, `BMP`, `DIB`) directly from raw RAM dumps (`.raw`, `.dmp`, `.vmem`).
- **Correct Chunk Overlap Offset Calculation**: Absolute evidence offsets are computed as `c["offset"] + offset_base - len(overlap_buffer)` — preventing ~1MB misattribution on multi-chunk streams.
- **SHA-256 Deduplication**: Carved payloads are deduplicated by cryptographic SHA-256 hash.
- **UUID-keyed Output Filenames**: Exported carve images use UUID suffixes to prevent overwrites across multiple dump sessions.

### 2. C2 Steganography & Covert Channel Extractors
- **Heuristic Byte-Stream Extractors** (Not true DCT domain decoders):
  - **F5 Matrix Embedding Decoder**: Syndrome matrix payload extraction from non-zero LSB coefficient byte streams.
  - **OutGuess 0.2 Extractor**: LCG PRNG-steered coefficient bit sequence extraction with configurable seeds.
  - **JSteg Extractor**: Byte-stream LSB extraction from JPEG entropy-coded scan data.
  - **Westfeld's Chi-Square ($\chi^2$) Analysis**: Mathematical test on Pairs of Values (PoVs) to detect LSB replacement.
  - **RS (Regular/Singular) Steganalysis**: Indicates potential LSB anomaly rate and estimates embedding capacity.
- **PNG Structural Anomaly Analyzer**:
  - Detects non-standard custom chunk injections (`coVT`, `stEG`).
  - Flags **CRC32 Checksum Mismatches** and decompresses `zTXt`/`iTXt` compressed metadata chunks.

### 3. Neural AI & Feature Extraction Pipeline
- **ONNX Model Inference**: Local execution for neural forensics models via ONNX Runtime.
  - Strict manifest schema validation: `input_size` (2 ints), `mean`/`std` (3 floats each), explicit `activation` (`softmax`/`sigmoid`/`none`).
  - Quantized `int8` model support with mandatory `quantization_scale` and `quantization_zero_point`.
  - Multi-input model rejection for forensic safety.
- **Academic Forensic Feature Layer**:
  - **High-Frequency Laplacian Residual Noise Energy**: Quantifies synthetic generator low-noise floor anomalies.
  - **Spatial Gradient Curvature & Smoothness Ratio**: Detects diffusion-generated smoothness signatures (Heuristic).
  - **Inter-Channel Chrominance Correlation ($r_{RG}$)**: Flags unnatural RGB alignment in AI generators.
- **Diffusion Prompt Injection Scanner**: Regex pattern scanner for EXIF/PNG parameters and OCR text to flag prompt injection vectors.

### 4. Bayesian Multi-Modal Risk Fusion & Scientific Evaluation Harness
- **Log-Odds Bayesian Fusion Engine** with default prior $P_0 = 0.10$ (realistic forensic base rate).
  - C2 Stego and Prompt Injection findings are fully wired into the Likelihood Ratio calculation.
  - **Fail-close behavior**: Any internal fusion exception returns `ANALYSIS_ERROR` — never silently defaults to `CLEAN`.
  - **Cache poisoning protection**: `ANALYSIS_ERROR` results are never written to disk cache.
- **Correlation Attenuation & Dependency Discounting**: Logarithmic decay applied to correlated indicators to prevent artificial posterior inflation.
- **Executable Benchmark Harness (`DatasetBenchmarkRunner`)**:
  - AUC inversion handling: when `AUC < 0.5`, TP/FP/TN/FN thresholds flip to `s ≤ threshold`.
  - **Balanced Accuracy** metric `(TPR + TNR) / 2` added for class-imbalanced forensic datasets.
  - Youden J index optimal threshold search across all unique score candidates.

### 5. Polling-based Directory Watcher & Sandbox Dynamic Ingestion
- **Continuous Artifact Drop Monitor (`--watch-dir`)**: Real-time polling watcher on evidence dropzones.
  - **Note:** Uses point-in-time OS process snapshots (`tasklist`/`ps`) — not kernel-level ETW/Sysmon/inotify tracing. Short-lived writer processes may not be captured.
- **Sandbox Ingestion (`--sandbox-dir`)**: Ingests automated sandbox run directories, scans for credential leaks via OCR.
  - Failed artifact ingestions are logged with a `failed_ingestions` counter — no silent failures.
  - Artifact paths reported as relative paths from `sandbox_dir` to disambiguate subdirectories.
  - **Note:** Parses visual screenshots only — does not ingest raw Cuckoo/CAPE telemetry JSON (process trees, API logs).

### 6. OCR & Confidential Secret Leak Hunter
- **Secret & API Key Hunter**: Scans screenshots and documents for exposed credentials:
  - AWS Access Key ID (`AKIA...`) & Secret Access Keys
  - GitHub Tokens (`ghp_...`, `github_pat_...`)
  - OpenAI Secret Keys (`sk-...`, `sk-proj-...`)
  - Slack API Tokens (`xoxb-...`, `xoxp-...`)
  - Asymmetric Private Keys (`BEGIN RSA/OPENSSH PRIVATE KEY`)
  - Cleartext Passwords (`password = "..."`, `db_pass`)
  - Payment Cards (validated via Luhn checksum)
  - Turkish National ID (TC Kimlik) & US Social Security Numbers
  - Cryptocurrency Seed Recovery Phrases (12/24 BIP39 word sequences)

### 7. SOC Threat Hunting & Forensic Chain of Custody
- **Automated YARA Rule Generator (`--generate-yara`)**: Compiles deployable `.yar` rules matching detected hashes, magic headers, webshell patterns, and embedded payloads.
- **MISP JSON Event Exporter (`--misp`)**: Generates standardized MISP threat events with classified IOCs and attributes.
- **STIX 2.1 Threat Intelligence Bundles (`--stix`)**: Exports threat actor bundles with file hashes and network IOCs.
- **ISO/IEC 27037 Tamper-Evident Chained Audit Ledger (`--case-id`, `--examiner`)**: Cryptographically links every audit record via SHA-256 seal, enabling full chain-of-custody verification.

### 8. Image Tampering & Physics-Based Forensics
- **Multi-Scale Error Level Analysis (ELA)**: Evaluates compression disparity across calibrated qualities ($Q \in \{70, 80, 90\}$).
- **Splice & Noise Inconsistency Map**: Block-wise high-pass Laplacian noise variance mapping.
- **Copy-Move (Cloning) Keypoint Detector**: ORB keypoint descriptor clustering to flag cloned regions.
- **Extended DQT Hardware/Software Database**: 50+ profiles for Apple iPhone 11-16 Pro, Samsung Galaxy S20-S24 Ultra, Google Pixel, Canon, Nikon, Sony, DJI Drones, Photoshop, Lightroom, GIMP, and WhatsApp/Telegram transcoders.
- **CFA Bayer Demosaicing Anomaly Detection**: Detects disruptions in camera sensor color interpolation grids.
- **8x8 DCT Block Grid Phase Shift**: Identifies pasted patches misaligned with the global 8x8 DCT grid phase.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yxdooo/lensint.git
cd lensint

# Install with all extensions (FastAPI, OpenCV, Pytest, Bandit)
pip install -e ".[all]"
```

---

## CLI Usage Examples

```bash
# 1. Full evidence examination with STIX, MISP, and YARA rule export
lensint evidence.jpg \
  --case-id "CASE-2026-0042" \
  --examiner "ForensicAnalyst_44" \
  --html report.html \
  --json data.json \
  --stix stix_bundle.json \
  --misp misp_event.json \
  --generate-yara rule.yar \
  --geo-lookup

# 2. Carve volatile image buffers from raw RAM memory dump
lensint --carve-memory memory_dump.raw

# 3. Ingest and correlate dynamic sandbox run artifacts (CAPE / Cuckoo)
lensint --sandbox-dir /opt/cuckoo/storage/analyses/42/

# 4. Start continuous real-time artifact watcher on evidence directory
lensint --watch-dir /var/log/suricata/files/

# 5. Extract trailing overlay payload
lensint suspicious_carrier.png --extract-overlay extracted_payload.bin
```

---

## Web UI & REST API

Launch the hardened FastAPI server:

```bash
lensint serve --host 127.0.0.1 --port 8000
```

Open `http://localhost:8000` in your browser to access the interactive web interface with drag-and-drop analysis, visual heatmaps, OCR secret leak inspector, and one-click MISP/YARA/STIX exports.

---

## Running Automated Unit Tests

```bash
# Run all 73 modular unit tests across forensic engines
pytest tests/ -v --cov=lensint
```

---

## License

Distributed under the **MIT License**. See `LICENSE` for more information.


