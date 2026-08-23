# Lensint v3.5 Enterprise

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688.svg)](https://fastapi.tiangolo.com/)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1%20Ready-green.svg)](https://oasis-open.github.io/cti-documentation/)
[![MISP](https://img.shields.io/badge/MISP-Event%20Ready-red.svg)](https://www.misp-project.org/)
[![YARA](https://img.shields.io/badge/YARA-Auto%20Generator-orange.svg)](https://virustotal.github.io/yara/)
[![Volatility 3](https://img.shields.io/badge/Volatility%203-Plugin%20Ready-blueviolet.svg)](https://github.com/volatilityfoundation/volatility3)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-Passing-brightgreen.svg)](https://github.com/yxdooo/lensint/actions)

**Lensint** is a modular digital image forensics, AI/Deepfake detection, and cybersecurity threat intelligence framework. Engineered for security researchers, incident responders (DFIR), SOC analysts, OSINT investigators, and digital forensic examiners, Lensint inspects digital images across multiple forensic dimensions to expose localized tampering, cloning, steganographic carriers, covert exfiltration channels, synthetic AI generation, confidential credential leaks, memory dump artifacts, and camera/software footprints.

---

## Key Capabilities

### 1. Memory Forensics & Volatility 3 In-Memory Scanner (`--carve-memory`)
- **Volatile RAM Dump Carver**: Carves image buffers (`PNG`, `JPEG`, `BMP`, `DIB`) directly from raw RAM dumps (`.raw`, `.dmp`, `.vmem`), clipboard allocations, and browser texture caches.
- **Volatility 3 Plugin Integration**: Native plugin interface (`VolatilityLensintPlugin`) with standard requirements, layer scanning, and tree grid generators for process memory and kernel heap allocations.
- **In-Memory Buffer Scanner**: Detects concealed in-memory webshells and stego images unmapped on disk.

### 2. C2 Steganography & Covert Channel Exfiltration Decoders
- **Frequency & Matrix Embedding Stego Decoders**:
  - **F5 Matrix Embedding Decoder**: Decodes $(1, 2^k - 1, k)$ syndrome matrix embedding across non-zero DCT coefficient streams.
  - **OutGuess 0.2 Extractor**: LCG PRNG-steered DCT coefficient bit sequence extraction with configurable seeds.
  - **JSteg AC Carver**: JPEG entropy-coded scan data bitstream carver following SOS markers.
  - **Westfeld's Chi-Square ($\chi^2$) Analysis**: Mathematical test on Pairs of Values (PoVs) to detect LSB replacement.
  - **RS (Regular/Singular) Steganalysis**: Quantifies LSB replacement rate and estimates embedding capacity.
- **PNG Covert Channel & Chunk Anomaly Analyzer**:
  - Detects non-standard custom chunk injections (`coVT`, `stEG`).
  - Flags and extracts **CRC32 Checksum Parity Covert Channels** (tampered checksum fields carrying exfiltrated bits).
  - Decompresses `zTXt`/`iTXt` hidden compression tunnels.
  - Identifies IDAT chunk size fragmentation attacks.

### 3. Deep Learning AI & Multi-Spectral Neural Feature Extractor
- **ONNX Model Inference with Model Manifest Negotiation**: Local execution support for neural forensics models (`TruFor`, `CNNDetection`, `UniversalFakeDetect`, `Swin-Transformer`) with configurable preprocessing and tensor shapes.
- **Multi-Dimensional Academic Forensic Feature Layer**:
  - **High-Frequency Laplacian Residual Noise Energy**: Quantifies synthetic generator low-noise floor anomalies.
  - **Spatial Gradient Curvature & Smoothness Ratio**: Detects diffusion-generated smoothness signatures.
  - **Inter-Channel Chrominance Correlation ($r_{RG}$)**: Flags unnatural RGB alignment in AI generators.
- **Diffusion Prompt Injection & Jailbreak Hunter**: Scans image EXIF/PNG parameters and OCR text for prompt injection vectors (`"Ignore previous instructions"`, `"DAN Mode"`, `"[SYSTEM PROMPT]"`).

### 4. Bayesian Multi-Modal Risk Fusion & Scientific Evaluation Harness
- **Context-Aware Prior Probabilities**: Configurable priors for DFIR incident triage ($P_0 = 0.20$), wild social media OSINT ($P_0 = 0.05$), and criminal evidence inquiry ($P_0 = 0.50$).
- **Correlation Attenuation & Dependency Discounting**: Applies logarithmic decay to correlated indicators (e.g. ELA + DQT recompression overlap) to prevent artificial posterior inflation.
- **Executable Benchmark Harness (`DatasetBenchmarkRunner`)**: Ingests ground-truth labeled datasets (CASIA v2.0, CoMoFoD, BOSSBase, ForenSynths), computes empirical confusion matrices, and calculates ROC-AUC dynamically.

### 5. Endpoint Evidence Watcher & Sandbox Dynamic Ingestion
- **Continuous Artifact Drop Monitor (`--watch-dir`)**: Real-time event loop watching evidence dropzones and triggering instant multi-dimensional forensic analysis.
- **Process Attribution Telemetry**: Captures active process snapshots (PID, process name, command line) to correlate newly dropped image artifacts with potential writer processes.
- **CAPE / Cuckoo Sandbox Ingestion (`--sandbox-dir`)**: Ingests automated sandbox run directories, correlates desktop screenshots, scans for credential leaks via OCR, and produces an automated sandbox threat verdict (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`).

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
- **Automated YARA Rule Generator (`--generate-yara`)**: Compiles deployable `.yar` rules matching detected hashes, magic headers, webshell patterns, and embedded payloads. Supports native `yara-python` compilation with transparent fallback.
- **MISP JSON Event Exporter (`--misp`)**: Generates standardized MISP threat events with classified IOCs and attributes.
- **STIX 2.1 Threat Intelligence Bundles (`--stix`)**: Exports threat actor bundles with file hashes and network IOCs.
- **ISO/IEC 27037 Tamper-Evident Chained Audit Ledger (`--case-id`, `--examiner`)**: Cryptographically links every audit record to the preceding record's SHA-256 seal (`previous_record_seal`), enabling full chain-of-custody verification (`verify_audit_chain`).

### 8. Image Tampering & Physics-Based Forensics
- **Multi-Scale Error Level Analysis (ELA)**: Evaluates compression disparity across calibrated qualities ($Q \in \{70, 80, 90\}$).
- **Splice & Noise Inconsistency Map**: Block-wise high-pass Laplacian noise variance mapping.
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
# Run all 69 modular unit tests across 25 forensic engines
pytest tests/ -v --cov=lensint
```

---

## License

Distributed under the **MIT License**. See `LICENSE` for more information.
