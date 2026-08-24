# Lensint v3.6 Enterprise

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688.svg)](https://fastapi.tiangolo.com/)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1%20Ready-green.svg)](https://oasis-open.github.io/cti-documentation/)
[![MISP](https://img.shields.io/badge/MISP-Event%20Ready-red.svg)](https://www.misp-project.org/)
[![YARA](https://img.shields.io/badge/YARA-Auto%20Generator-orange.svg)](https://virustotal.github.io/yara/)
[![Tests](https://img.shields.io/badge/tests-120%20passed-brightgreen.svg)](https://github.com/yxdooo/lensint/actions)

LENSINT is an enterprise-grade digital image and video forensics, AI detection, and threat intelligence framework built for cyber crime units (Law Enforcement / EGM / Europol / Interpol / FBI), court-appointed expert witnesses, incident responders, and forensic laboratories. It integrates physics-based tampering analysis with PRNU camera sensor matching, Meta PDQ perceptual hashing, video GOP cadence analysis, C2 steganography extraction, RFC 3161 cryptographic timestamping, and courtroom-admissible PDF expert witness reporting.

---

## Key Capabilities

### 1. Courtroom Expert Witness & Legal Admissibility (`--pdf-report`, `--tsa-server`)
- **Official Courtroom PDF Expert Witness Report Engine**: Generates legally admissible reports compliant with Federal Rules of Evidence (FRE 702 / 901), Daubert Standards, and ISO/IEC 27037:2012.
  - Case metadata, Evidence Custody Ledger, Cryptographic Hash Table (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `SSDEEP`, `Meta PDQ`).
  - RFC 3161 TSA digital timestamp token verification & ISO 27037 chained ledger seal.
  - Daubert Standard empirical error rate disclosure (CASIA v2.0, CoMoFoD, BOSSBase).
  - Unambiguous Expert Witness Opinion & Legal Conclusion.
- **RFC 3161 Trusted Timestamping Protocol (TSP)**: Automatically queries accredited public TSAs via ASN.1 DER `TimeStampReq` structures with fallback air-gapped cryptographic time-seals.

### 2. Camera Sensor PRNU Device Identification & 1:N Matching (`lensint.modules.prnu`)
- **Photo-Response Non-Uniformity (PRNU)**: Isolates unique sensor silicon imperfections via 2D adaptive spatial/wavelet Wiener noise filtering ($W = I - F(I)$).
- **Peak-to-Correlation Energy (PCE)**: 2D-FFT circular cross-correlation computes definitive device match metrics ($\text{PCE} \ge 60.0 \rightarrow \text{False Alarm Rate} < 10^{-6}$).
- **Maximum Likelihood Estimation (MLE) Fingerprint Generator**: Combines multiple flat calibration photos to synthesize reference camera sensor models ($\hat{K}$).
- **1:N Law Enforcement Suspect Device Database**: Rapidly correlates anonymous images against thousands of registered suspect smartphones and cameras.

### 3. Advanced Video Forensics & Temporal GOP Splicing (`lensint.modules.video_forensics`)
- **ISOBMFF / QuickTime Atom Tree Parsing**: Deep structural inspection of MP4, MOV, MKV, and AVI containers (`ftyp`, `moov`, `mdat`, `trak`, `udta`).
- **Trailing Video Overlay Carving**: Detects and extracts hidden C2 steganography payloads appended past the `mdat` container boundary.
- **Editing Software Signatures**: Flags footprints from Adobe Premiere Pro, DaVinci Resolve, Apple Final Cut Pro, FFmpeg (Lavf/Lavc), HandBrake, and CapCut.
- **H.264/H.265 NAL Unit & GOP Cadence Analysis**: Parses NAL bitstreams (I/P/B frames) to detect temporal scene cuts, frame drops, and double video compression.

### 4. Meta PDQ 256-Bit Perceptual Hashing & BK-Tree Triage (`lensint.modules.pdq_hash`)
- **Meta PDQ Perceptual Hashing**: Computes 256-bit 2D-DCT perceptual hashes resistant against image resizing, compression, cropping, and color adjustment.
- **Burkhard-Keller Metric Tree (BK-Tree)**: Sub-millisecond similarity range queries ($D_H \le 31$) across millions of illicit content hashes using triangle inequality pruning.
- **Zero-Knowledge Investigator Privacy Mode**: Enables law enforcement threat matching without rendering sensitive visual pixels on screen.

### 5. Memory Forensics & Volatility 3 Plugin (`lensint/volatility_plugin/lensint_carve.py`)
- **Official Volatility 3 Plugin (`windows.lensint_carve`)**: Scans process VADs and volatile RAM dumps for uncommitted GDI/DIB surfaces, in-memory textures, and C2 stego carrier buffers.
- **Balanced Multi-Format Stream Carver**: Recovers PNG, JPEG, WEBP, GIF, and BMP structures from memory dumps with exact global offset attribution.

### 6. C2 Steganography & DCT-Domain Extractors
- **Pure-Python JPEG Baseline DCT Engine (`jpeg_dct.py`)**:
  - Full Huffman table construction and entropy-coded scan decoding for Baseline Sequential JPEGs (SOF0).
  - **DRI & RST0–RST7 Restart Marker Support**: Discards sub-byte bit alignment and resets DC predictors to zero across restart intervals.
  - **Multi-Scan / Multi-SOS Support**: Iterates through sequential scans with structured telemetry.
- **DCT-Domain Steganography Analyzers**:
  - **JSteg DCT Payload Extractor**: Recovers LSB payloads across AC coefficients with Shannon entropy telemetry.
  - **F5 Matrix Embedding Analyzer**: Calculates carrier capacity from non-zero AC coefficients and flags LSB skew.
  - **OutGuess 0.2 DCT Statistical Symmetry Analyzer**: Quantifies histogram symmetry preservation anomaly.
  - **Westfeld's Chi-Square ($\chi^2$) Analysis**: Mathematical test on Pairs of Values (PoVs) to detect LSB replacement.
  - **Calibrated RS Steganalysis**: Texture-variance guarded RS analysis with 0.08 threshold to eliminate false positives on flat images.
- **PNG Structural Anomaly Analyzer**: Validates IHDR/IEND lengths, detects IDAT sequence fragmentation, checks CRC32 mismatches, and inspects non-standard ancillary chunks.

### 7. Neural AI & Forensic Feature Extraction
- **ONNX Model Inference**: Local execution for neural forensics models via ONNX Runtime with strict SHA-256 and manifest integrity verification.
- **Academic Forensic Feature Layer**:
  - High-frequency noise floor consistency & inter-channel residual correlation.
  - Spatial gradient curvature & smoothness ratio.
  - Multi-factor composite AI scoring (2D FFT periodic spikes, GAN upsampling fingerprints, diffusion residuals).
- **Prompt Injection Scanner**: Regex pattern scanner for EXIF/PNG parameters and OCR text to flag prompt injection vectors.

### 8. Bayesian Multi-Modal Risk Fusion & Scientific Benchmark Harness
- **Log-Odds Bayesian Fusion Engine** with default prior $P_0 = 0.10$ and two-sided likelihood ratios for negative evidence dampening.
- **Correlation Attenuation & Dependency Discounting**: Logarithmic decay applied to correlated indicators to prevent artificial posterior inflation.
- **Executable Benchmark Harness (`DatasetBenchmarkRunner`)**: AUC inversion handling, Youden J index threshold optimization, and balanced accuracy metrics.

### 9. SOC Threat Hunting, Sandbox Ingestion & OCR Credential Scanner
- **Automated YARA Rule Generator (`--generate-yara`)**: Compiles deployable `.yar` rules matching detected hashes, magic headers, webshell patterns, and embedded payloads.
- **MISP JSON Event Exporter (`--misp`)**: Generates standardized MISP threat events with classified IOCs and attributes.
- **STIX 2.1 Threat Intelligence Bundles (`--stix`)**: Exports threat actor bundles with file hashes and network IOCs.
- **Dynamic Sandbox Telemetry Ingestion (`--sandbox-dir`)**: Ingests and correlates CAPE / Cuckoo dynamic sandbox process trees, network IOCs, and execution screenshots.
- **Secret & API Key Hunter**: Scans screenshots and documents for AWS keys, GitHub tokens, OpenAI keys, Slack tokens, private keys, passwords, and payment cards.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yxdooo/lensint.git
cd lensint

# Install with all extensions (FastAPI, OpenCV, ReportLab, Pytest)
pip install -e ".[all]"
```

---

## CLI Usage Examples

```bash
# 1. Official Courtroom Expert Witness PDF Report (ISO/IEC 27037 Compliant)
lensint evidence.jpg \

```bash
# 1. Official Courtroom Expert Witness PDF Report (ISO/IEC 27037 Compliant)
lensint evidence.jpg \
  --case-id "CASE-2026-CRIM-4402" \
  --examiner "Dr. Jane Doe, Ph.D." \
  --pdf-report "Courtroom_Expert_Report.pdf" \
  --html "interactive_report.html" \
  --json "forensic_data.json"

# 2. Extract Hidden Steganography & Trailing Payloads
lensint carrier.png --extract-overlay "extracted_payload.bin"

# 3. Threat Hunting & SOC Rule Generation (STIX 2.1, MISP, YARA)
lensint malware_sample.jpg \
  --stix "threat_bundle.json" \
  --misp "misp_event.json" \
  --generate-yara "malware_rules.yar"

# 4. Ingest and correlate dynamic sandbox run artifacts (CAPE / Cuckoo)
lensint --sandbox-dir /opt/cuckoo/storage/analyses/42/ --html /reports/live.html

# 5. Start high-performance REST API & Web UI server
lensint serve --port 8000
```

---

## Running Automated Unit Tests

```bash
# Run all 120 rigorous unit & integration tests across forensic engines
pytest tests/ -v
```

---

## License

Distributed under the **MIT License**. See `LICENSE` for more information.



