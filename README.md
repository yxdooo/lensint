# LENSINT: Enterprise Digital Media Forensics, Steganography Extraction, and Multi-Modal Threat Intelligence Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688.svg)](https://fastapi.tiangolo.com/)
[![ISO/IEC 27037](https://img.shields.io/badge/ISO%2FIEC-27037%20Compliant-brightgreen.svg)](https://www.iso.org/standard/44381.html)
[![RFC 3161](https://img.shields.io/badge/RFC-3161%20TSP%20Timestamping-blue.svg)](https://www.rfc-editor.org/rfc/rfc3161)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1%20Ready-green.svg)](https://oasis-open.github.io/cti-documentation/)
[![MISP](https://img.shields.io/badge/MISP-Event%20Ready-red.svg)](https://www.misp-project.org/)
[![YARA](https://img.shields.io/badge/YARA-Auto%20Generator-orange.svg)](https://virustotal.github.io/yara/)
[![Tests](https://img.shields.io/badge/tests-121%20passed-brightgreen.svg)](tests/)

LENSINT is an enterprise-grade digital image and video forensics, steganographic payload extraction, and threat intelligence analysis framework. Designed for cybercrime units (Law Enforcement / Europol / Interpol / Federal Agencies), accredited digital forensics and incident response (DFIR) laboratories, and court-appointed expert witnesses, the system integrates physics-based tampering verification, camera sensor identification via Photo-Response Non-Uniformity (PRNU), Meta PDQ 256-bit perceptual hashing, video container atom and Group of Pictures (GOP) cadence analysis, Command and Control (C2) steganography decoding, RFC 3161 cryptographic timestamping, and courtroom-admissible PDF expert witness reporting compliant with Federal Rules of Evidence (FRE 702/901) and ISO/IEC 27037:2012 standards.

---

## System Architecture

The following diagram illustrates the multi-stage ingestion, concurrent forensic processing pipeline, calibrated Bayesian risk fusion engine, cryptographically sealed audit ledger, and reporting subsystem.

```
                    +--------------------------------------------+
                    |           Input Evidence File              |
                    |   (JPEG, PNG, WebP, GIF, MP4, MOV, RAW)    |
                    +---------------------+----------------------+
                                          |
                        +-----------------v------------------+
                        |      Decompression Bomb Guard      |
                        |      & SHA-256 Cache Lookup        |
                        +-----------------+------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                 |                                 |
+-------v-------+                 +-------v-------+                 +-------v-------+
|  Integrity &  |                 |  Metadata &   |                 | Video & GOP   |
| Magic Preamble|                 | EXIF / GPS /  |                 | Cadence Splicing|
| (MD5/SHA256)  |                 | SSIM Thumbnail|                 | (ISOBMFF/NAL) |
+-------+-------+                 +-------+-------+                 +-------+-------+
        |                                 |                                 |
+-------v-------+                 +-------v-------+                 +-------v-------+
| Physics-Based |                 | Stego & C2    |                 | Camera Sensor |
| Tampering     |                 | Decoders      |                 | PRNU 1:N      |
| (ELA/DQT/CFA) |                 | (JSteg/F5/RS) |                 | Matching (MLE)|
+-------+-------+                 +-------+-------+                 +-------+-------+
        |                                 |                                 |
+-------v-------+                 +-------v-------+                 +-------v-------+
| Meta PDQ Hash |                 | Neural AI &   |                 | Strings, OCR, |
| & BK-Tree     |                 | ONNX Pipeline |                 | IOCs & YARA   |
| Triage Index  |                 | (TruFor/Grad) |                 | Polyglots     |
+-------+-------+                 +-------+-------+                 +-------+-------+
        |                                 |                                 |
        +---------------------------------+---------------------------------+
                                          |
                        +-----------------v------------------+
                        |   Calibrated Bayesian Log-Odds     |
                        |   Fusion Engine (P0, TPR, FPR)     |
                        +-----------------+------------------+
                                          |
                        +-----------------v------------------+
                        |  ISO/IEC 27037 Chained Audit Trail |
                        |  & RFC 3161 TSA Timestamp Token   |
                        +-----------------+------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                 |               |                |                |
+-------v-------+ +-------v-------+ +-----v-----+ +--------v--------+ +-----v-----+
| FRE 702 Expert| | Interactive   | | Machine   | | Threat Bundles  | | Deployable|
| Witness PDF   | | Dark-Mode     | | JSON      | | (STIX 2.1 &     | | YARA      |
| Court Report  | | HTML Report   | | Data      | | MISP Events)    | | Rule File |
+---------------+ +---------------+ +-----------+ +-----------------+ +-----------+
```

---

## Core Capabilities

### 1. Courtroom Expert Witness Reporting and Legal Admissibility
- **FRE 702 / 901 and Daubert Standard Compliance**: Generates publication-grade, courtroom-admissible PDF expert witness reports incorporating chain of custody ledgers, cryptographic verification tables (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `SSDEEP`, `Meta PDQ`), forensic visual plates, empirical error rate disclosures, and formal expert witness opinions.
- **RFC 3161 Trusted Timestamping Protocol (TSP)**: Automatically constructs ASN.1 DER `TimeStampReq` structures and queries accredited public TSAs via HTTP `application/timestamp-query` to prove digital evidence existence and integrity at a precise UTC point in time, with automatic fallback to air-gapped cryptographic time seals.
- **ISO/IEC 27037:2012 Chained Audit Ledger**: Implements sequential hash-chaining across all analysis records where each record incorporates the SHA-256 seal of the preceding entry, ensuring mathematical tamper-evidence for courtroom presentation.

### 2. Camera Sensor PRNU Device Identification and 1:N Matching (`lensint.modules.prnu`)
- **Noise Residual Extraction**: Isolates physical sensor silicon imperfections $W = I - F(I)$ using an adaptive 2D spatial Wiener denoising filter with robust median absolute deviation noise variance estimation ($\sigma_0^2$) and linear artifact zero-mean normalization.
- **Peak-to-Correlation Energy (PCE)**: Executes 2D-FFT circular cross-correlation between the image noise residual and a candidate sensor fingerprint. Matches meeting $\text{PCE} \ge 60.0$ provide definitive device attribution with an estimated theoretical False Alarm Rate $\text{FAR} < 10^{-6}$.
- **Maximum Likelihood Estimation (MLE) Fingerprint Synthesis**: Combines flat calibration photos to synthesize reference camera sensor models:
  $$\hat{K} = \frac{\sum_i W_i I_i}{\sum_i I_i^2}$$
- **1:N Law Enforcement Database**: Indexes suspect smartphones and hardware cameras to match anonymous visual evidence against known device repositories in sub-second intervals.

### 3. Video Forensics, ISOBMFF Parsing, and GOP Cadence Analysis (`lensint.modules.video_forensics`)
- **Container Structure Parsing**: Performs deep recursive inspection of ISO Base Media File Format (ISOBMFF / QuickTime MP4, MOV), Matroska (MKV), and AVI containers (`ftyp`, `moov`, `mdat`, `trak`, `udta`).
- **Trailing Overlay Carving**: Detects and extracts hidden data and C2 steganographic payloads appended past the `mdat` container boundary.
- **Editing Footprint Signatures**: Scans container metadata for editing signatures including Adobe Premiere Pro, DaVinci Resolve, Apple Final Cut Pro, FFmpeg (`Lavf`/`Lavc`), HandBrake, and CapCut.
- **H.264/H.265 NAL Unit & GOP Analysis**: Scans Annex B and AVCC length-prefixed NAL bitstreams (I/P/B frames) to evaluate keyframe intervals; flags temporal splicing when GOP standard deviation exceeds threshold ($\sigma_{GOP} > 4.0$).

### 4. Meta PDQ 256-Bit Perceptual Hashing and BK-Tree Triage (`lensint.modules.pdq_hash`)
- **256-Bit Perceptual Hashing**: Generates 256-bit perceptual hashes invariant against resizing, format conversion, compression, and moderate cropping using Jarosz domain filtering, a $16 \times 64$ 2D-DCT projection matrix, and AC coefficient median quantization.
- **Burkhard-Keller Metric Tree (BK-Tree)**: Sub-millisecond similarity range queries ($D_H \le 31$) across millions of target hashes utilizing triangle inequality metric space pruning:
  $$|d(u, q) - d(u, v)| \le r$$
- **Zero-Knowledge Privacy Mode**: Allows forensic investigators to identify illicit media matches without exposing sensitive visual content on monitor screens.

### 5. C2 Steganography and DCT-Domain Frequency Decoders (`lensint.modules.jpeg_dct`, `lensint.modules.c2_stego_decoders`)
- **Pure-Python Baseline JPEG DCT Engine (`jpeg_dct.py`)**: Full Huffman table construction and entropy-coded scan decoding for Baseline Sequential JPEGs (SOF0), featuring DRI (Define Restart Interval) and RST0-RST7 restart marker handling with sub-byte bit alignment reset and DC predictor synchronization.
- **JSteg DCT Extractor**: Recovers LSB payloads embedded in non-zero AC DCT coefficients ($\neq 0, \pm 1$) and measures Shannon entropy to identify encrypted or compressed data streams.
- **F5 Matrix Embedding Analyzer**: Computes $(1, 2^k - 1, k)$ embedding capacity from non-zero AC coefficients and quantifies histogram shrinkage.
- **OutGuess 0.2 Statistical Symmetry Analyzer**: Evaluates histogram symmetry preservation anomalies across Pairs of Values (PoVs).
- **Westfeld Chi-Square ($\chi^2$) Analysis**: Applies goodness-of-fit testing on PoV frequencies to detect LSB replacement:
  $$\chi^2 = \sum_{k=1}^m \frac{(y_{2k} - y_{2k}^*)^2}{y_{2k}^*}, \quad y_{2k}^* = \frac{y_{2k} + y_{2k+1}}{2}$$
- **Calibrated RS Steganalysis**: Quantifies regular and singular group count variations under dual inversion masks, with variance gating ($0.08$) to prevent false positives on flat surfaces.
- **PNG Structure Inspection**: Validates IHDR/IEND lengths, detects IDAT chunk fragmentation, flags CRC32 checksum tampering, and decompresses `zTXt`/`iTXt` metadata tunnels.

### 6. Physics-Based Tampering and Integrity Verification (`lensint.modules.tampering`)
- **Multi-Scale Error Level Analysis (ELA)**: Evaluates compression disparity across calibrated JPEG qualities ($Q \in \{80, 90, 95\}$) and identifies localized editing via 32x32 block discrepancy ($P_{95} - \text{Median}$).
- **Copy-Move Cloning Detection**: Extracts ORB keypoint descriptors with BFMatcher k-NN ($k=3$), Lowe's ratio test ($0.75$), spatial separation constraints ($>40$ px), and RANSAC affine inlier verification, reinforced by 16x16 block DCT lexicographical sorting.
- **JPEG Ghost Detection**: Scans recompression curves across $Q \in [50..95]$ with step 5 to identify spliced fragments originating from disparate compression generations.
- **DQT Hardware Fingerprinting**: Matches $8 \times 8$ luminance/chrominance quantization matrices against hardware camera profiles (Apple iPhone 11-16 Pro, Samsung Galaxy S20-S24 Ultra, Google Pixel 6-9 Pro, Canon EOS, Nikon D/Z, Sony Alpha, DJI Drones) and editing software (Adobe Photoshop, Lightroom, GIMP, Canva).
- **CFA Bayer Demosaicing**: Evaluates RGGB color filter array interpolation continuity to expose splicing.
- **8x8 DCT Block Grid Shift**: Detects misaligned patch insertions where the local grid phase does not match the global JPEG boundary ($(dx, dy) \neq (0,0)$).
- **Radial Chromatic Aberration Vectors**: Quantifies radial optical dispersion convergence across image quadrants to detect composites photographed with different lenses.
- **Illumination Surface Normal Vectors**: Analyzes 2D gradient circular statistics ($\text{atan2}(I_y, I_x)$) to uncover lighting direction conflicts.

### 7. Neural AI, Deepfake Detection, and Feature Extraction (`lensint.modules.neural_ai`)
- **ONNX Model Inference**: Executes neural forensic classifiers (`TruFor`, `CNNDetection`, Swin-Transformer) via ONNX Runtime with strict SHA-256 hash manifest verification.
- **Academic Feature Extraction**: Computes Laplacian noise energy, spatial gradient curvature, inter-channel chrominance correlation ($r_{RG}$), and 2D-FFT spectral periodicity for GAN upsampling grids and diffusion footprints.
- **Prompt Injection Scanner**: Regex engine scanning EXIF/PNG metadata and OCR text for adversarial LLM jailbreak vectors (`Ignore previous instructions`, `DAN mode`).

### 8. Calibrated Bayesian Risk Fusion and Benchmarking (`lensint.modules.benchmarks`)
- **Log-Odds Bayesian Fusion Engine**: Configurable prior probability $P_0$ (triage: 0.20, courtroom: 0.50, sandbox: 0.75) with two-sided likelihood ratios and correlation group attenuation ($1 / (1 + 1.5 \cdot c_g)$) to eliminate probability inflation from correlated compression indicators.
- **Dataset Benchmark Runner**: Evaluates ground-truth labeled datasets (CASIA v2.0, CoMoFoD, BOSSBase, ForenSynths), computing Wilcoxon-Mann-Whitney ROC-AUC, Hanley-McNeil 95% Confidence Intervals, and optimal Youden's J statistic thresholds.

### 9. Volatility 3 Memory Forensics Plugin (`lensint/volatility_plugin/lensint_carve.py`)
- **Official Volatility 3 Plugin (`windows.lensint_carve`)**: Traverses process Virtual Address Descriptors (VADs) and heap allocations to locate and carve uncommitted GDI/DIB surfaces and memory-resident C2 stego carrier buffers.
- **Stream-Carver Engine**: Recovers raw PNG, JPEG, WEBP, GIF, and BMP structures from physical memory dumps (`.raw`, `.dmp`, `.vmem`) with absolute hex offset reporting.

### 10. Threat Intelligence, Dynamic Sandbox Ingestion, and OCR Secret Scanner
- **Automated YARA Generation (`--generate-yara`)**: Automatically compiles deployable `.yar` rules matching detected file hashes, magic headers, webshell patterns, and extracted payloads.
- **MISP & STIX 2.1 Exporters (`--misp`, `--stix`)**: Exports standardized MISP threat events and STIX 2.1 JSON bundles with classified IOCs (IPv4, domains, URLs, Base64 blobs).
- **Dynamic Sandbox Ingestion (`--sandbox-dir`)**: Ingests and correlates CAPE / Cuckoo dynamic sandbox execution runs, analyzing process trees, network captures, and runtime desktop screenshots.
- **OCR Secret Hunter (`lensint.modules.ocr_scan`)**: Extracts text via Tesseract OCR and scans for leaked credentials, including AWS keys, GitHub tokens, OpenAI keys, Slack tokens, private keys, passwords, and Luhn-validated credit cards.

---

## Installation

### Prerequisites
- Python 3.9 or higher
- C/C++ compiler and CMake (for optional accelerated libraries)
- Tesseract OCR engine (optional, for visual credential extraction)

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/yxdooo/lensint.git
cd lensint

# Install standard distribution
pip install -e .

# Install with all extensions (FastAPI, OpenCV, ReportLab, Volatility 3, Pytest)
pip install -e ".[all]"
```

---

## Command Line Interface (CLI)

### Argument Reference

| Option | Argument | Description |
| :--- | :--- | :--- |
| `-v`, `--version` | None | Display LENSINT version string and exit |
| `--pdf`, `--pdf-report` | `PATH` | Generate an official courtroom-grade Expert Witness PDF report (ISO/IEC 27037 compliant) |
| `--html` | `PATH` | Export standalone interactive dark-mode HTML forensic report |
| `--json` | `PATH` | Export machine-readable JSON forensic findings |
| `--stix` | `PATH` | Export standardized STIX 2.1 Threat Intelligence Bundle |
| `--misp` | `PATH` | Export standardized MISP JSON Threat Event format |
| `--generate-yara` | `PATH` | Generate deployable YARA detection rule (`.yar`) matching detected threats and hashes |
| `--extract-overlay` | `PATH` | Extract binary payload appended past image/video container EOF |
| `--carve-memory` | `PATH` | Carve and analyze volatile image buffers from RAM dump (`.raw`, `.dmp`, `.vmem`) |
| `--out-dir` | `DIR` | Directory to save extracted artifacts (carved memory images, dumps) |
| `--watch-dir` | `DIR` | Run EDR real-time filesystem monitor for newly dropped evidence files |
| `--sandbox-dir` | `DIR` | Ingest and correlate dynamic sandbox run execution artifacts (CAPE / Cuckoo) |
| `--tsa-server` | `URL` | RFC 3161 Time-Stamp Authority (TSA) endpoint for evidence timestamping |
| `--case-id` | `ID` | Forensic Case Identifier recorded in cryptographically sealed audit ledger |
| `--examiner` | `NAME` | Name of forensic examiner recorded in chain of custody |
| `--audit-log` | `PATH` | Custom path to append cryptographically sealed forensic audit log entry |
| `--no-audit` | None | Suppress chain of custody audit trail recording |
| `--geo-lookup` | None | Reverse geocode EXIF GPS tags into physical street address |
| `--ela-quality` | `INT` | JPEG recompression quality for Error Level Analysis (default: 90) |
| `--min-string-len`| `INT` | Minimum length for ASCII/UTF-16 string extraction (default: 4) |
| `--no-cache` | None | Bypass on-disk SHA-256 result cache and force complete re-analysis |
| `--no-visuals` | None | Disable generation of visual ELA/thumbnails for maximum processing speed |
| `--batch` | None | Process all supported image and video files within target directory |
| `-q`, `--quiet` | None | Suppress detailed console tables and output only final forensic verdict |

### Usage Examples

#### 1. Official Courtroom Expert Witness Examination (ISO/IEC 27037 & RFC 3161)
```bash
lensint evidence.jpg \
  --case-id "CASE-2026-CRIM-4402" \
  --examiner "Dr. Jane Doe, Ph.D." \
  --pdf-report "Courtroom_Expert_Report.pdf" \
  --html "interactive_report.html" \
  --json "forensic_data.json" \
  --tsa-server "https://freetsa.org/tsr"
```

#### 2. Steganography Payload Extraction
```bash
lensint carrier.png --extract-overlay "extracted_payload.bin"
```

#### 3. Threat Hunting & SOC Rule Generation (STIX 2.1, MISP, YARA)
```bash
lensint malware_sample.jpg \
  --stix "threat_bundle.json" \
  --misp "misp_event.json" \
  --generate-yara "malware_rules.yar"
```

#### 4. Volatile RAM Memory Dump Image Carving
```bash
lensint --carve-memory /dumps/infected_host.raw --out-dir /carved_evidence/
```

#### 5. Dynamic Sandbox Ingestion (CAPE / Cuckoo)
```bash
lensint --sandbox-dir /opt/cuckoo/storage/analyses/1337/
```

#### 6. Real-Time Directory Artifact Monitoring
```bash
lensint --watch-dir /var/log/suricata/extracted_files/
```

#### 7. REST API & Web UI Service Daemon
```bash
lensint serve --host 0.0.0.0 --port 8000
```

---

## REST API Reference

LENSINT provides a high-performance REST API powered by FastAPI.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health status, version, and active configuration summary |
| `GET` | `/` | Serves the interactive drag-and-drop web UI |
| `POST` | `/api/analyze` | Analyzes uploaded media file and returns complete JSON forensic report |
| `POST` | `/api/analyze/html` | Analyzes uploaded media file and streams standalone interactive HTML report |
| `POST` | `/api/analyze/pdf` | Generates and streams official Courtroom Expert Witness PDF report |
| `POST` | `/api/analyze/batch` | Concurrently processes multiple uploaded files with error isolation |
| `GET` | `/api/cache/stats` | Inspects SHA-256 forensic cache utilization and disk footprint |
| `DELETE` | `/api/cache` | Purges on-disk forensic result cache |

### cURL API Example
```bash
curl -X POST "http://localhost:8000/api/analyze?generate_visuals=false&geo_lookup=true" \
     -H "X-API-Key: YOUR_SECRET_KEY" \
     -F "file=@evidence.jpg"
```

---

## Running Automated Verification Tests

LENSINT includes a comprehensive test suite covering all forensic modules, mathematical algorithms, parsers, and reporting pipelines.

```bash
# Execute test suite
pytest tests/ -v

# Run with test coverage metrics
pytest --cov=lensint tests/ -v
```

---

## Technical Documentation Index

Detailed technical specifications and module references are available in the `docs/` directory:

- [REST API Specification](docs/api.md): Endpoints, schemas, authentication, and integration examples.
- [System Architecture](docs/architecture.md): Pipeline data flow, Bayesian fusion formulas, and mathematical models.
- [Audit & Chain of Custody](docs/audit_and_chain_of_custody.md): ISO/IEC 27037 ledger chaining, RFC 3161 TSP, and FRE 702 Daubert admissibility.
- [CLI User Manual](docs/cli.md): Comprehensive parameter guide, incident response scenarios, and usage patterns.
- [Configuration Guide](docs/configuration.md): Environment variables, ONNX model manifest schema, and deployment settings.
- [Forensic Modules Reference](docs/modules.md): In-depth algorithms, mathematical formulations, and engineering mechanics for every module.

---

## License

Distributed under the **MIT License**. See `LICENSE` for complete terms and conditions.
