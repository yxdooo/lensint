# Lensint

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688.svg)](https://fastapi.tiangolo.com/)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1%20Ready-green.svg)](https://oasis-open.github.io/cti-documentation/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](Dockerfile)

**Lensint** is a modular, high-precision digital image forensics, AI/Deepfake detection, and cybersecurity threat intelligence framework. Engineered for security researchers, incident responders (DFIR), SOC analysts, OSINT investigators, and courtroom-grade digital forensic analysts, Lensint inspects digital images across multiple forensic dimensions to expose localized tampering, cloning, steganographic carriers, hidden payloads, synthetic AI generation, and camera/software footprints.

---

## Table of Contents

- [Core Capabilities](#core-capabilities)
- [Courtroom-Grade Tampering & Manipulation Analysis](#courtroom-grade-tampering--manipulation-analysis)
- [Advanced Cybersecurity & Anti-Stego Modules](#advanced-cybersecurity--anti-stego-modules)
- [Mathematical & Algorithmic Foundations](#mathematical--algorithmic-foundations)
- [Installation](#installation)
- [CLI Usage & Examples](#cli-usage--examples)
- [Interactive Web UI & REST API](#interactive-web-ui--rest-api)
- [STIX 2.1 Threat Intelligence Export](#stix-21-threat-intelligence-export)
- [Architecture](#architecture)
- [Running Unit Tests](#running-unit-tests)
- [License](#license)

---

## Core Capabilities

1. **File Integrity & Cryptographic Hashes**:
   - Multi-algorithm cryptographic hashing: `MD5`, `SHA-1`, `SHA-256`, and `SHA-512`.
   - Magic byte container validation (`JPEG`, `PNG`, `GIF`, `WebP`, `BMP`, `TIFF`).
   - Extension spoofing detection (e.g., executable or script payloads disguised as image files).
   - Container structure verification (detecting corrupted, damaged, or truncated headers).

2. **Metadata & Geolocation OSINT**:
   - Comprehensive EXIF IFD tag extraction (Camera make/model, serial numbers, lens profiles, exposure, ISO, flash, metering).
   - GPS coordinate extraction with DMS-to-Decimal conversion and direct OpenStreetMap / Google Maps integration.
   - **Reverse Geocoding**: Automated physical address resolution via OpenStreetMap Nominatim API.
   - **Social Media Provenance Sizing**: Footprint detection for images compressed and stripped by WhatsApp, Telegram, Twitter/X, or Instagram.
   - **EXIF Thumbnail SSIM Mismatch**: Validates embedded preview thumbnails against the main image to detect selective retouches.
   - **Logical Timestamp Anomalies**: Flags impossible chronologies (ModifyDate precedes DateTimeOriginal, future dates, GPS vs EXIF drift).
   - XMP XML parsing and IPTC editorial metadata extraction.

3. **AI & Synthetic Image (Deepfake) Detection**:
   - **2D Fast Fourier Transform (FFT)** magnitude spectrum analysis: Identifies high-frequency periodic grid artifacts left by diffusion model latent upsamplers.
   - **GAN Transpose Convolution Fingerprints**: Detects checkerboard spectral energy peaks characteristic of GAN architectures.
   - **PRNU (Photo Response Non-Uniformity) Hardware Sensor Modeling**: Distinguishes genuine optical camera sensor noise from synthetic noise-free AI generations.
   - **Regional Inpainting / Anomaly Detection**: Highlights localized gradient variance discrepancies from generative fill or object removal.
   - **C2PA / Content Credentials**: Scans for Adobe Content Authenticity Initiative manifests and provenance markers.
   - **Prompt Parameter Extraction**: Extracts positive/negative prompts, seed, steps, sampler, CFG scale, and model hashes embedded by Stable Diffusion, ComfyUI, and Automatic1111.

4. **Steganography & Carrier Extraction**:
   - **Trailing Overlay Detection**: Scans for appended payloads hidden beyond container EOF markers (`FF D9` for JPEG, `IEND` for PNG, `00 3B` for GIF).
   - **RS (Regular/Singular) Steganalysis**: Quantifies LSB replacement embedding and estimates hidden capacity utilization.
   - **Stego Tool Signatures**: Detects footprints left by OpenStego, SilentEye, JPHide, StegHide, and F5.
   - **3-Channel LSB Shannon Entropy**: Multi-channel (R, G, B) and interleaved entropy calculation to flag stego carriers.
   - **Bit-Plane Slicing**: Visual extraction of individual bit planes (Plane 0 LSB through Plane 7 MSB).

5. **Malware, WebShell & YARA Rules**:
   - **Native YARA Engine**: Built-in YARA rule matching for WebShells (`eval` + `base64_decode`), Cobalt Strike stagers, Reverse Shells, and PE executables.
   - **Auto-Deobfuscator**: 1-Byte XOR brute-force scanner automatically decoding hidden C2 endpoints and shell commands.
   - **High-Entropy Section Slicing**: Detects packed, compressed, or encrypted payload sections (Shannon Entropy > 7.5).
   - **Polyglot Container Identification**: `GIFAR`, `PNG-PHP`, `JPEG-PHP`, `GIF-ZIP`, and `PNG-ZIP`.

6. **IOC Threat Hunting & Threat Intelligence**:
   - Extraction of ASCII and UTF-16 strings with regex-based IOC extraction (IPv4, IPv6, URLs, `.onion` hidden services, Emails, Base64 blobs, shell execution keywords, crypto wallets).
   - Automated direct lookup links for VirusTotal, HybridAnalysis, AbuseIPDB, Shodan, and ThreatFox.
   - Direct reverse image search integration with Google Lens, Bing Visual Search, Yandex Images, and TinEye.
   - **STIX 2.1 Threat Intelligence Bundles**: Export standardized threat bundles for direct ingestion into SIEM / SOAR / MISP platforms.

---

## Courtroom-Grade Tampering & Manipulation Analysis

Lensint integrates 12 dedicated image manipulation analysis techniques to deliver verifiable forensic proof:

| Forensic Method | Technique / Principle | Evidence Detected |
| :--- | :--- | :--- |
| **Multi-Scale ELA** | Differential recompression matrix across $Q \in \{70, 80, 90\}$ | Localized compression variance from saved edits |
| **Splice Detection** | Block-wise Laplacian variance & thermal noise mapping | Foreign spliced regions with inconsistent sensor noise |
| **Copy-Move (Cloning)** | ORB keypoint clustering + 16x16 DCT Block Matching fallback | Duplicated/cloned regions pasted within same image |
| **JPEG Ghosts** | Multi-quality compression sweeper ($Q \in [50..95]$) | Double compression & spliced elements from other JPEGs |
| **DQT Quantization Forensics** | $8\times8$ Luminance/Chrominance table signature matching | Camera hardware vs Photoshop/GIMP encoder mismatch |
| **CFA Demosaicing Analysis** | Residual variance across Bayer Color Filter Array pattern | Broken interpolation grid from splicing or inpainting |
| **8x8 DCT Block Grid Shift** | Spatial energy distribution across 64 phase offsets | Pasted patches misaligned with background $8\times8$ grid |
| **Chromatic Aberration** | Optical radial vector alignment relative to image center | Pasted objects photographed with a different physical lens |
| **Median Filtering** | First-order pixel difference zero-ratio histogram | Anti-forensic smoothing used to conceal edit boundaries |
| **Illumination Consistency** | Surface normal gradient vectors across quadrants | Conflicting primary light angles in composite photos |
| **Thumbnail SSIM Verification** | Structural Similarity comparison of EXIF preview vs image | Selective tampering where embedded thumbnail was not updated |
| **Social Media Footprinting** | Platform-specific quantization, resolution, and header matching | Tracing re-encoded origins (WhatsApp, Telegram, Twitter, Instagram) |

---

## Installation

### Standard Installation

```bash
git clone https://github.com/yxdooo/lensint.git
cd lensint
pip install -e .
```

### Full Installation (Server + OpenCV + STIX)

```bash
pip install -e ".[all]"
```

---

## CLI Usage & Examples

### Single Image Analysis

```bash
# Terminal forensic report
lensint evidence.jpg

# Export standalone interactive HTML report and JSON summary
lensint evidence.png --html report.html --json report.json

# Export STIX 2.1 threat intelligence bundle
lensint suspicious.jpg --stix threat_bundle.json

# Extract hidden overlay payloads past image EOF
lensint carrier.png --extract-overlay payload.bin

# Perform reverse geocoding on GPS coordinates
lensint photo.jpg --geo-lookup
```

### Batch Directory Analysis

```bash
# Analyze all images in directory with per-file reports
lensint ./cases/case_042/ --batch --html case_report.html --json case_data.json
```

---

## Interactive Web UI & REST API

Launch the local web server:

```bash
lensint serve --port 8000
```

- **Drag-and-Drop Web UI**: Open `http://localhost:8000` in your browser for single or batch drag-and-drop forensic analysis with real-time visual heatmaps.
- **REST API Endpoints**:
  - `POST /api/analyze` — Returns comprehensive JSON forensic data.
  - `POST /api/analyze/html` — Returns standalone interactive HTML report.
  - `POST /api/analyze/batch` — Multi-file batch upload and analysis.
  - `GET /api/cache/stats` — View on-disk SHA-256 cache performance.
  - `DELETE /api/cache` — Clear forensic cache.

---

## STIX 2.1 Threat Intelligence Export

Lensint outputs standardized **STIX 2.1 Bundles** ready for ingestion into SIEM / SOAR / Threat Intelligence platforms (MISP, OpenCTI, Splunk, Microsoft Sentinel):

```bash
lensint malware_sample.png --stix threat_bundle.json
```

---

## Running Unit Tests

Lensint includes a comprehensive automated test suite covering all forensic modules:

```bash
pytest tests/ -v
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
