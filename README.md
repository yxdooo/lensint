# Lensint v3.5 Enterprise

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688.svg)](https://fastapi.tiangolo.com/)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1%20Ready-green.svg)](https://oasis-open.github.io/cti-documentation/)
[![MISP](https://img.shields.io/badge/MISP-Event%20Ready-red.svg)](https://www.misp-project.org/)
[![YARA](https://img.shields.io/badge/YARA-Auto%20Generator-orange.svg)](https://virustotal.github.io/yara/)
[![Volatility 3](https://img.shields.io/badge/Volatility%203-Plugin%20Ready-blueviolet.svg)](https://github.com/volatilityfoundation/volatility3)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-Passing-brightgreen.svg)](https://github.com/yxdooo/lensint/actions)

**Lensint** is an enterprise-grade digital image forensics, AI/Deepfake detection, and cybersecurity threat intelligence framework. Engineered for security researchers, incident responders (DFIR), SOC analysts, OSINT investigators, and courtroom-grade digital forensic examiners, Lensint inspects digital images across multiple forensic dimensions to expose localized tampering, cloning, steganographic carriers, hidden payloads, synthetic AI generation, confidential credential leaks, memory dump artifacts, and camera/software footprints.

---

## Key Capabilities

### 1. Memory Forensics & Volatility 3 In-Memory Scanner (`--carve-memory`)
- **Volatile RAM Dump Carver**: Carves image buffers (`PNG`, `JPEG`, `BMP`, `DIB`) directly from raw RAM dumps (`.raw`, `.dmp`, `.vmem`), clipboard allocations, and browser texture caches.
- **Volatility 3 Plugin Integration**: Native plugin interface (`VolatilityLensintPlugin`) allowing direct forensic scanning of process memory layers and kernel heap allocations.
- **Process Memory Bitmap Scanner**: Detects concealed in-memory webshells and stego images unmapped on disk.

### 2. C2 Steganography & Covert Channel Exfiltration Decoders
- **DCT Frequency Stego Decoders**: Detects frequency modulation carriers: **JSteg, JPHide, F5 Matrix Embedding, OutGuess 0.2, and Hide4PGP**.
- **PNG Covert Channel & Chunk Anomaly Analyzer**:
  - Detects non-standard chunk injections (`coVT`, `stEG`).
  - Flags **CRC32 Checksum Covert Channels** (tampered checksums carrying hidden bits).
  - Decompresses `zTXt`/`iTXt` hidden compression tunnels.
  - Detects suspicious IDAT fragmentation attacks.

### 3. Deep Learning & Transformer Deepfake Detection Layer
- **ONNX Model Inference Pipeline**: Local execution support for neural forensics models (`TruFor`, `CNNDetection`, `UniversalFakeDetect`).
- **Diffusion Prompt Injection & Jailbreak Hunter**: Scans image EXIF/PNG parameters and OCR text for prompt injection vectors (`"Ignore previous instructions"`, `"DAN Mode"`, `"[SYSTEM PROMPT]"`).

### 4. Kernel-Level EDR Monitor & Sandbox Dynamic Ingestion
- **EDR Real-Time File Drop Monitor (`--watch-dir`)**: Watches directories in real time (simulating Windows Minifilter / Linux eBPF probe file-drop triggers) and performs instant forensic audits.
- **CAPE / Cuckoo Sandbox Dynamic Ingester (`--sandbox-dir`)**: Ingests automated sandbox run directories, correlates desktop screenshots, scans for credential leaks via OCR, and produces an automated sandbox threat verdict (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`).

### 5. OCR & Confidential Secret Leak Hunter
- **Secret & API Key Hunter**: Scans screenshots and documents for exposed credentials:
  - AWS Access Key ID (`AKIA...`) & Secret Access Keys
  - GitHub Tokens (`ghp_...`, `github_pat_...`)
  - OpenAI Secret Keys (`sk-...`, `sk-proj-...`)
  - Slack API Tokens (`xoxb-...`, `xoxp-...`)
  - Asymmetric Private Keys (`BEGIN RSA/OPENSSH PRIVATE KEY`)
  - Cleartext Passwords (`password = "..."`, `db_pass`)
  - Payment Cards (validated via Luhn algorithm)
  - Turkish National ID (TC Kimlik) & US Social Security Numbers
  - Cryptocurrency Seed Recovery Phrases (12/24 BIP39 word sequences)

### 6. SOC/EDR Threat Hunting & Intelligence Export
- **Automated YARA Rule Generator (`--generate-yara`)**: Automatically compiles deployable `.yar` rules matching detected hashes, magic headers, webshell patterns, and embedded payloads.
- **MISP JSON Event Exporter (`--misp`)**: Generates standardized MISP threat events with classified IOCs and attributes.
- **STIX 2.1 Threat Intelligence Bundles (`--stix`)**: Exports threat actor bundles with file hashes and network IOCs.
- **ISO/IEC 27037 Forensic Chain of Custody (`--case-id`, `--examiner`)**: Creates cryptographically sealed audit records with SHA-256 integrity verification seals.

### 7. Advanced Steganography Extraction & Analysis
- **Automatic LSB Carver**: Carves nested embedded files (`ZIP`, `PNG`, `PDF`, `EXE`, `ELF`, `7z`, `RAR`) from raw LSB bitstreams with vectorized NumPy acceleration.
- **Stego Passphrase Dictionary Attack**: Tests carriers against common stego wordlists (OpenStego, StegHide).
- **Palette Steganalysis**: Detects micro-variant parity modulations in PNG/GIF PLTE color tables.
- **RS (Regular/Singular) Steganalysis**: Quantifies LSB replacement embedding and estimates embedding capacity.
- **Trailing Overlay Extractor (`--extract-overlay`)**: Carves hidden payloads appended past container EOF markers.

### 8. Courtroom-Grade Tampering Forensics
- **Multi-Scale Error Level Analysis (ELA)**: Evaluates compression disparity across calibrated qualities ($Q \in \{70, 80, 90\}$).
- **Splice & Noise Inconsistency Map**: Visualizes block-wise high-pass Laplacian noise variance.
- **Copy-Move (Cloning) Keypoint Detector**: ORB keypoint descriptor clustering to flag cloned regions.
- **Extended DQT Hardware/Software Database**: 50+ profiles for Apple iPhone 11-16 Pro, Samsung Galaxy S20-S24 Ultra, Google Pixel, Canon, Nikon, Sony, DJI Drones, Photoshop, Lightroom, GIMP, and WhatsApp/Telegram transcoders.
- **CFA Bayer Demosaicing**: Detects disruptions in camera sensor color interpolation grids.
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

# 4. Start real-time EDR file drop monitor on directory
lensint --watch-dir /var/log/suricata/files/

# 5. Extract trailing overlay payload
lensint suspicious_carrier.png --extract-overlay extracted_payload.bin
```

---

## Web UI & REST API

Launch the high-performance local web server:

```bash
lensint serve --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` in your browser to access the interactive web interface with drag-and-drop analysis, courtroom visual heatmaps, OCR secret leak inspector, and one-click MISP/YARA/STIX exports.

---

## Running Automated Unit Tests

```bash
# Run all 64 modular unit tests
pytest tests/ -v
```

---

## License

Distributed under the **MIT License**. See `LICENSE` for more information.
