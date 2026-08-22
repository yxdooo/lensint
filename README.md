# Lensint

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](Dockerfile)

**Lensint** is a modular, high-precision digital image forensics, AI/Deepfake detection, and cybersecurity threat intelligence framework. Engineered for security researchers, incident responders, OSINT investigators, and courtroom-grade digital forensic analysts, Lensint inspects digital images across multiple forensic dimensions to expose localized tampering, cloning, steganographic carriers, hidden payloads, synthetic AI generation, and camera/software footprints.

---

## Table of Contents

- [Core Forensic Modules](#core-forensic-modules)
- [Courtroom-Grade Tampering & Manipulation Analysis](#courtroom-grade-tampering--manipulation-analysis)
- [Mathematical & Algorithmic Foundations](#mathematical--algorithmic-foundations)
- [Installation](#installation)
- [CLI Usage & Examples](#cli-usage--examples)
- [Headless REST API](#headless-rest-api)
- [Docker Deployment](#docker-deployment)
- [Architecture](#architecture)
- [Running Unit Tests](#running-unit-tests)
- [License](#license)

---

## Core Forensic Modules

1. **File Integrity & Cryptographic Hashes**:
   - Multi-algorithm cryptographic hashing: `MD5`, `SHA-1`, `SHA-256`, and `SHA-512`.
   - Magic byte container validation (`JPEG`, `PNG`, `GIF`, `WebP`, `BMP`, `TIFF`).
   - Extension spoofing detection (e.g., executable or script payloads disguised as image files).
   - Container structure verification (detecting corrupted, damaged, or truncated headers).

2. **Metadata & Geolocation OSINT**:
   - Comprehensive EXIF IFD tag extraction (Camera make/model, serial numbers, lens profiles, exposure, ISO, flash, metering).
   - GPS coordinate extraction with DMS-to-Decimal conversion and direct OpenStreetMap / Google Maps integration.
   - Reverse Geocoding: Automated physical address resolution via OpenStreetMap Nominatim API.
   - Software Footprinting: Tracing editing tools (Adobe Photoshop, Lightroom, GIMP, Canva, Snapseed, VSCO) and AI generation workflows.
   - XMP XML parsing and IPTC editorial metadata extraction.

3. **AI & Synthetic Image (Deepfake) Detection**:
   - **2D Fast Fourier Transform (FFT)** magnitude spectrum analysis: Identifies high-frequency periodic grid artifacts left by diffusion model latent upsamplers (Stable Diffusion, Midjourney, DALL-E).
   - **C2PA / Content Credentials**: Scans for Adobe Content Authenticity Initiative manifests and provenance markers.
   - **Prompt Parameter Extraction**: Extracts positive/negative prompts, seed, steps, sampler, CFG scale, and model hashes embedded by Stable Diffusion, ComfyUI, and Automatic1111.

4. **Steganography & Carrier Extraction**:
   - **Trailing Overlay Detection**: Scans for appended payloads hidden beyond container EOF markers (`FF D9` for JPEG, `IEND` for PNG, `3B` for GIF).
   - **Automated Carrier Extraction**: Extracts and validates embedded file headers (ZIP, RAR, 7z, Executable PE/ELF, PDF, SQLite, PHP) hidden inside image bodies or LSB channels.
   - **LSB Shannon Entropy**: Measures entropy per color channel (Red, Green, Blue) to flag high-randomness stego carriers.
   - **Bit-Plane Slicing**: Visual extraction of individual bit planes (Plane 0 LSB through Plane 7 MSB).

5. **Malware, WebShell & Polyglot Rules**:
   - Polyglot container identification: `GIFAR`, `PNG-PHP`, `JPEG-PHP`, `GIF-ZIP`, and `PNG-ZIP`.
   - WebShell signature hunting: Obfuscated PHP loaders (`eval` + `base64_decode` / `gzinflate`), dynamic command execution hooks, and cookie-based stego webshells.
   - Shellcode & Evasion: Detects x86/x64 NOP sleds, execve stack shellcode, and PowerShell AMSI bypass sequences.

6. **IOC Threat Hunting & Intelligence**:
   - Extraction of ASCII and UTF-16 strings with regex-based IOC extraction (IPv4, IPv6, URLs, `.onion` hidden services, Emails, Base64 blobs, shell execution keywords, crypto wallets).
   - Automated direct lookup links for VirusTotal, HybridAnalysis, AbuseIPDB, Shodan, and ThreatFox.
   - Direct reverse image search integration with Google Lens, Bing Visual Search, Yandex Images, and TinEye.

---

## Courtroom-Grade Tampering & Manipulation Analysis

Lensint integrates 10 dedicated image manipulation analysis techniques to deliver verifiable forensic proof:

| Forensic Method | Technique / Principle | Evidence Detected |
| :--- | :--- | :--- |
| **Error Level Analysis (ELA)** | Differential recompression matrix at calibrated quality | Localized compression variance from saved edits |
| **Copy-Move (Cloning)** | ORB keypoint descriptor clustering & Euclidean distance | Duplicated/cloned regions pasted within same image |
| **JPEG Ghosts** | Multi-quality compression sweeper ($Q \in [50..95]$) | Double compression & spliced elements from other JPEGs |
| **DQT Quantization Forensics** | $8\times8$ Luminance/Chrominance table signature matching | Camera hardware vs Photoshop/GIMP encoder mismatch |
| **CFA Demosaicing Analysis** | Residual variance across Bayer Color Filter Array pattern | Broken interpolation grid from splicing or inpainting |
| **8x8 DCT Block Grid Shift** | Spatial energy distribution across 64 phase offsets | Pasted patches misaligned with background $8\times8$ grid |
| **Chromatic Aberration** | Optical radial vector alignment relative to image center | Pasted objects photographed with a different physical lens |
| **Median Filtering** | First-order pixel difference zero-ratio histogram | Anti-forensic smoothing used to conceal edit boundaries |
| **Illumination Consistency** | Surface normal gradient vectors across quadrants | Conflicting primary light angles in composite photos |
| **Sensor Noise Variance** | High-pass Laplacian filter local variance mapping | Foreign sensor noise from image splicing |

---

## Mathematical & Algorithmic Foundations

### 1. 2D Fast Fourier Transform (FFT) Power Spectrum
Natural camera sensors exhibit smooth frequency decay across radial distributions. Latent diffusion models introduce periodic high-frequency grid spikes during transposed convolutional upsampling:

$$\mathcal{F}(u, v) = \sum_{x=0}^{M-1} \sum_{y=0}^{N-1} f(x, y) e^{-j 2\pi \left(\frac{ux}{M} + \frac{vy}{N}\right)}$$

Lensint computes the log magnitude spectrum $\log(|\mathcal{F}(u, v)| + 1)$ and calculates the radial peak-to-noise ratio in the high-frequency band ($0.25 < r < 0.48$) to detect synthetic generation.

### 2. JPEG Ghost Double-Compression Detection
When an image region originally compressed at quality $Q_a$ is pasted into a background compressed at $Q_b$, recompressing the composite image across qualities $q \in [1..100]$ minimizes difference at the original compression point:

$$D(x, y, q) = |I(x, y) - I_q(x, y)|$$

Regions reaching their local minimum difference at distinctly different $q$ values provide mathematical proof of composite splicing.

### 3. Shannon Entropy for Steganography
Unmodified natural images exhibit lower entropy in their least significant bits. Injected encrypted or compressed payloads approach maximum randomness (8.0 bits per byte):

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Lensint calculates $H(X)$ across each color plane and triggers an alert if the average LSB entropy exceeds $7.95$.

---

## Installation

### Prerequisites
- Python 3.8 or higher
- `pip` package manager

### Standard Installation
```bash
git clone https://github.com/yxdooo/lensint.git
cd lensint
pip install -r requirements.txt
pip install -e .
```

---

## CLI Usage & Examples

### Basic Analysis (Terminal Console)
```bash
lensint sample.jpg
```

### Generate Standalone Dark-Mode HTML Forensic Report
```bash
lensint suspect.png --html report.html
```

### Export Comprehensive JSON Report
```bash
lensint suspect.png --json analysis.json
```

### Perform Reverse Geocoding (OSINT Address Lookup)
```bash
lensint photo.jpg --geo-lookup
```

### Extract Appended / Hidden Overlay Payload
```bash
lensint carrier.png --extract-overlay dumped_payload.bin
```

### Batch Directory Scan
```bash
lensint /path/to/evidence_folder/ --batch
```

### CLI Options Reference

| Argument | Flag | Description |
| :--- | :--- | :--- |
| `target` | Positional | Target image file path, directory, or `serve` command. |
| `--html` | `REPORT_PATH` | Generate standalone interactive dark-mode HTML report. |
| `--json` | `REPORT_PATH` | Export comprehensive forensic analysis as structured JSON. |
| `--batch` | - | Enable recursive batch scanning across directory. |
| `--geo-lookup` | - | Query Nominatim API for human-readable reverse geocoding. |
| `--extract-overlay` | `OUT_FILE` | Extract trailing overlay bytes past image EOF to disk. |
| `--ela-quality` | `INT` | JPEG quality level for ELA recompression (default: `90`). |
| `--min-string-len` | `INT` | Minimum character length for string extraction (default: `4`). |
| `-q, --quiet` | - | Suppress tables and display only executive verdict. |
| `-v, --version` | - | Show Lensint version number. |

---

## Headless REST API

Lensint includes a built-in high-performance REST API powered by FastAPI.

### Start the API Server
```bash
lensint serve --host 0.0.0.0 --port 8000
```

Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

### API Endpoints

#### 1. `POST /api/analyze` (JSON Response)
```bash
curl -X POST "http://localhost:8000/api/analyze" \
  -F "file=@target.jpg" \
  -F "geo_lookup=true"
```

#### 2. `POST /api/analyze/html` (HTML Report Response)
```bash
curl -X POST "http://localhost:8000/api/analyze/html" \
  -F "file=@target.jpg" \
  -F "geo_lookup=true" -o report.html
```

#### 3. `GET /health` (Health Check)
```bash
curl "http://localhost:8000/health"
```

---

## Docker Deployment

Deploy Lensint as an isolated containerized service:

```bash
# 1. Build the Docker container image
docker build -t lensint:2.0 .

# 2. Run the headless REST API service on port 8000
docker run -d -p 8000:8000 --name lensint-service lensint:2.0

# 3. Verify health status
curl http://localhost:8000/health
```

---

## Architecture

```
lensint/
├── cli.py                  # CLI routing, subcommands, and argument parsing
├── server.py               # FastAPI headless REST API server
├── core/
│   ├── analyzer.py         # Main analysis orchestrator and scoring engine
│   └── models.py           # Strongly-typed dataclass schemas
├── modules/
│   ├── integrity.py        # Magic bytes, MIME, and cryptographic hashing
│   ├── metadata.py         # EXIF, XMP, IPTC, and software footprinting
│   ├── ai_detect.py        # 2D FFT spectral analysis & C2PA / diffusion prompts
│   ├── tampering.py        # Deep tampering: ELA, Copy-Move, JPEG Ghosts, DQT, CFA, Grid, CA, Median, Lighting
│   ├── stego.py            # Overlay detection, LSB entropy, payload extraction
│   ├── malware_rules.py    # Polyglot, WebShell, and shellcode detection
│   ├── strings_scan.py     # String extraction and IOC threat hunting
│   └── threat_intel.py     # Reverse geocoding & OSINT query link generation
├── reporters/
│   ├── console.py          # Rich-based terminal reporting
│   ├── json_rep.py         # JSON serialization
│   └── html_rep.py         # Standalone HTML interactive reporting
└── utils/
    ├── gps.py              # Geolocation DMS parsing and map URL builders
    ├── image_ops.py        # PIL and numpy array transformations
    └── signatures.py       # Signature database for containers and payloads
```

---

## Running Unit Tests

Lensint includes an automated test suite verifying all forensic analysis modules:

```bash
python -m unittest tests/test_v2.py
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
