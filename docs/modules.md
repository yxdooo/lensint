# LENSINT Forensic & Security Modules Reference Guide

## Overview

This technical specification provides an exhaustive breakdown of every analytical engine, mathematical algorithm, structural parser, and threat hunting module within LENSINT v3.6.

---

## 1. File Structure & Cryptographic Integrity (`lensint.modules.integrity`)

The integrity subsystem validates file preambles, identifies extension disguises, computes multi-algorithm cryptographic fingerprints, and contextualizes digital screen captures.

- **Magic Byte Validation**: Direct binary inspection of container header signatures:
  - JPEG: `FF D8 FF`
  - PNG: `89 50 4E 47 0D 0A 1A 0A`
  - GIF: `47 49 46 38 37 61` / `47 49 46 38 39 61`
  - WebP: `52 49 46 46 ... 57 45 42 50`
  - BMP: `42 4D`
  - TIFF: `49 49 2A 00` (Little-Endian) / `4D 4D 00 2A` (Big-Endian)
- **Extension Spoofing Heuristics**: Detects executable binaries (Windows PE `4D 5A`, Linux ELF `7F 45 4C 46`), scripts (`<?php`, `#!/bin/bash`, `<script`), and archive polyglots disguised with image extensions.
- **Cryptographic Fingerprinting**: Simultaneously computes `MD5`, `SHA-1`, `SHA-256`, and `SHA-512` hashes across the raw input stream.
- **Digital Screen Capture Contextualizer**: Evaluates file naming conventions, fixed screen dimensions (macOS Retina, Windows, iOS, Android), and sRGB color profiles. When an image is identified as a digital screen capture, camera sensor heuristics (PRNU, CFA demosaicing) are automatically contextualized to suppress false positives.

---

## 2. Metadata, OSINT & Footprinting (`lensint.modules.metadata`)

Extracts camera parameters, evaluates editing history, validates embedded thumbnails, and detects temporal clock manipulation.

- **EXIF Image File Directory (IFD) Engine**: Parses camera make, model, serial number, lens specifications, exposure time, aperture ($f$-number), ISO speed, focal length, and firmware version.
- **Reverse Geocoding**: Translates raw GPS latitude/longitude coordinates into physical street addresses, cities, and countries via OpenStreetMap Nominatim.
- **Social Media Fingerprinting**: Identifies metadata stripping, standard resizing dimensions, and compression artifacts characteristic of WhatsApp, Telegram, X/Twitter, and Instagram.
- **Thumbnail SSIM Divergence Check**: Extracts embedded EXIF thumbnails, downsamples the primary image to match thumbnail dimensions, and computes the Structural Similarity Index Measure (SSIM). SSIM scores below $0.80$ flag selective localized retouching where the embedded thumbnail reflects the original scene before modification.
- **Temporal Chronology Anomaly Detection**: Detects camera clock manipulation:
  - `ModifyDate` precedes `DateTimeOriginal`.
  - Future timestamp generation ($t > \text{UTC Now}$).
  - Discrepancies between EXIF capture time and GPS atomic clock stamps ($>120$ seconds).
- **XMP & IPTC Parser**: Extracts Dublin Core schemas, Adobe Photoshop edit history logs, and IPTC press agency credits.

---

## 3. Physics-Based Tampering & Manipulation Forensics (`lensint.modules.tampering`)

Courtroom-grade physical tampering verification algorithms for detecting splicing, cloning, and recompression anomalies.

1. **Multi-Scale Error Level Analysis (ELA)**: Recompresses the image across multiple calibrated JPEG quality levels ($Q \in \{80, 90, 95\}$). The pixel-wise error matrix $E(x,y) = |I(x,y) - I_Q(x,y)|$ is evaluated over $32 \times 32$ spatial blocks. Localized editing is flagged when the 95th percentile block error significantly deviates from the global median error ($P_{95} - \text{Median}$).
2. **Copy-Move (Cloning) Keypoint Matching**:
   - Detects duplicated regions using Oriented FAST and Rotated BRIEF (ORB) keypoint descriptors.
   - Matches descriptor vectors using Brute-Force $k$-NN ($k=3$).
   - Enforces Lowe's ratio test ($d_1 < 0.75 \cdot d_2$) and spatial distance filtering ($\Delta > 40$ px).
   - Validates geometric transformation consistency using RANSAC partial affine estimation (`estimateAffinePartial2D`).
   - Reinforced with $16 \times 16$ block Discrete Cosine Transform (DCT) lexicographical feature sorting for low-texture clones.
3. **JPEG Ghost Analysis**: Evaluates recompression error surfaces across $Q \in [50..95]$ with step size 5. Pinpoints spliced image fragments originating from foreign images with differing JPEG compression histories.
4. **DQT (Quantization Table) Hardware Fingerprinting**: Extracts $8 \times 8$ luminance and chrominance quantization tables from JPEG DQT markers (`0xFFDB`). Matches tables against a database of hardware camera profiles (Apple iPhone 11-16 Pro, Samsung Galaxy S20-S24 Ultra, Google Pixel 6-9 Pro, Canon EOS, Nikon D/Z, Sony Alpha, DJI Drones) and desktop software encoders (Adobe Photoshop, Lightroom, GIMP, Canva).
5. **Color Filter Array (CFA) Bayer Demosaicing**: Evaluates spatial continuity of color interpolation across RGGB Bayer grids to identify spliced patches that lack original sensor interpolation characteristics.
6. **8x8 DCT Block Grid Shift**: Detects misaligned patch insertions where the spliced element's $8 \times 8$ block boundary does not align with the host JPEG's global grid phase ($(dx, dy) \neq (0,0)$).
7. **Radial Chromatic Aberration Vectors**: Analyzes wavelength-dependent optical dispersion (lateral chromatic aberration). Quantifies red/blue radial shift vectors $\vec{v}(r)$ from the optical center to expose composite objects shot with different lenses.
8. **Median Filter Anti-Forensic Smoothing**: Quantifies residual differences between median-filtered and unfiltered pixel neighborhoods to detect anti-forensic smoothing applied to conceal splice seams.
9. **Illumination Surface Normal Vectors**: Computes 2D gradient circular statistics ($\text{atan2}(I_y, I_x)$) across image quadrants to evaluate light source direction consistency.
10. **High-Pass Laplacian Sensor Noise Mapping**: Computes block-wise Laplacian noise variance $\sigma^2$ across the image surface to flag spliced fragments with mismatched noise floors.

---

## 4. Camera Sensor PRNU Device Identification & 1:N Matching (`lensint.modules.prnu`)

Identifies individual physical camera hardware devices based on sensor silicon imperfections.

- **Adaptive Spatial Wiener Noise Residual**: Isolates sensor noise $W = I - F(I)$ via local adaptive 2D Wiener filtering with robust MAD noise variance estimation ($\sigma_0^2$).
- **Linear Artifact Suppression**: Subtracts horizontal and vertical mean vectors to eliminate CMOS readout lines and JPEG block artifacts.
- **Peak-to-Correlation Energy (PCE)**: 2D-FFT circular cross-correlation between noise residual $W$ and candidate sensor fingerprint $K$. PCE values $\ge 60.0$ yield theoretical False Alarm Rates $\text{FAR} < 10^{-6}$.
- **Maximum Likelihood Estimation (MLE) Fingerprint Synthesis**: Combines multiple flat calibration images to generate a clean camera sensor model:
  $$\hat{K} = \frac{\sum_i W_i \odot I_i}{\sum_i I_i^2}$$
- **1:N Suspect Camera Database (`PRNUDatabase`)**: Matches unknown visual evidence against registered suspect hardware camera profiles.

---

## 5. Meta PDQ 256-Bit Perceptual Hashing & BK-Tree Triage (`lensint.modules.pdq_hash`)

Perceptual image fingerprinting compliant with open industry standards for threat triage and illicit content matching.

- **256-Bit Perceptual Hashing**: Preprocesses image to $64 \times 64$ with Jarosz domain Box Blur, projects spatial matrix through an orthonormal $16 \times 64$ 2D-DCT basis matrix, and generates 256 binary bits via AC median thresholding.
- **Burkhard-Keller Metric Tree (`BKTreePDQIndex`)**: Indexes millions of 256-bit perceptual hashes in metric space, executing sub-millisecond similarity range queries ($D_H \le 31$) using triangle inequality distance pruning:
  $$|d(u, q) - d(u, v)| \le r$$
- **Zero-Knowledge Forensic Triage**: Enables automated threat correlation against known illicit media repositories without displaying sensitive visual imagery on screen.

---

## 6. Video Forensics, ISOBMFF Parsing & GOP Cadence (`lensint.modules.video_forensics`)

Structural container and temporal GOP splicing analysis for digital video containers.

- **ISOBMFF Container Box Hierarchy**: Parses MP4, MOV, MKV, and AVI atom box trees (`ftyp`, `moov`, `mdat`, `trak`, `udta`).
- **Trailing Video Overlay Carving**: Detects and extracts hidden data and C2 steganographic payloads appended past the `mdat` container boundary.
- **Editing Software Footprints**: Flags editing signatures from Adobe Premiere Pro, DaVinci Resolve, Apple Final Cut Pro, FFmpeg (`Lavf`/`Lavc`), HandBrake, CapCut, and Camtasia.
- **NAL Unit & Temporal GOP Splicing Analysis**: Scans Annex B and AVCC bitstreams (I/P/B frames). Evaluates keyframe spacing consistency; flags temporal video cutting/splicing when GOP standard deviation exceeds threshold ($\sigma_{GOP} > 4.0$).

---

## 7. Pure-Python Baseline JPEG DCT Engine (`lensint.modules.jpeg_dct`)

Low-level pure-Python bitstream parser for Baseline Sequential JPEGs (SOF0).

- **Huffman Table Construction**: Constructs DC and AC Huffman lookup tables from DHT segments (`0xFFC4`).
- **Restart Marker Synchronization (DRI / RST0-RST7)**: Accurately handles Define Restart Interval markers (`0xFFDD`). Upon encountering RST markers (`0xFFD0`–`0xFFD7`), the bitstream reader discards leftover sub-byte bits, aligns to the next byte boundary, and resets DC predictors to zero.
- **Scan Header Decoding**: Supports multi-scan and multi-SOS sequential data decoding without reliance on external C libraries.

---

## 8. C2 Steganography & Frequency-Domain Decoders (`lensint.modules.c2_stego_decoders`)

Advanced steganography analyzers and decoders designed for Command and Control (C2) threat hunting.

- **JSteg DCT Payload Extractor**: Extracts LSB bits embedded in non-zero AC DCT coefficients ($\neq 0, \pm 1$). Computes Shannon entropy and identifies embedded file headers (`PK\x03\x04`, `MZ`, `ELF`, `PDF`).
- **F5 Matrix Embedding Analyzer**: Evaluates $(1, 2^k - 1, k)$ matrix embedding capacity from non-zero AC coefficients and quantifies histogram shrinkage.
- **OutGuess 0.2 Histogram Symmetry Analyzer**: Quantifies histogram symmetry preservation anomalies across Pairs of Values (PoVs).
- **Westfeld Chi-Square ($\chi^2$) Analysis**: Applies goodness-of-fit testing on PoV frequencies to detect LSB replacement:
  $$\chi^2 = \sum_{k=1}^m \frac{(y_{2k} - y_{2k}^*)^2}{y_{2k}^*}, \quad y_{2k}^* = \frac{y_{2k} + y_{2k+1}}{2}$$
- **Calibrated RS Steganalysis**: Applies dual inversion flipping masks to quantify regular and singular group count variations, with texture-variance gating ($0.08$) to eliminate false alarms on flat images.
- **PNG Structural Anomaly Inspection**: Validates IHDR length (strictly 13 bytes) and color type/bit depth compatibility, checks CRC32 checksums, detects IDAT chunk sequence fragmentation, flags unregistered ancillary chunks, and decompresses `zTXt`/`iTXt` metadata tunnels.

---

## 9. Steganography, LSB Carving & Overlay Detection (`lensint.modules.stego`, `lensint.modules.stego_extract`)

- **Trailing Overlay Detection & Carver**: Identifies and extracts binary payloads appended past image End-of-File (EOF) markers (`0xFFD9` for JPEG, `IEND` for PNG, `0x3B` for GIF) via `--extract-overlay`.
- **Vectorized LSB File Carver**: Accelerated `np.packbits` extraction scanning the 8 RGB bit planes to carve embedded `ZIP`, `PNG`, `PDF`, `EXE`, `ELF`, `7z`, and JSON payloads.
- **Palette Micro-Variant Steganalysis**: Evaluates parity modulations in indexed color palette tables (PNG/GIF).

---

## 10. Malware, WebShells & YARA Rule Generator (`lensint.modules.malware_rules`, `lensint.reporters.yara_gen`)

- **Static YARA Threat Scanner**: Scans media payloads for generic PHP webshells (`eval(base64_decode(...))`, `passthru`, `system`), Cobalt Strike stagers, reverse shells, and PE header signatures.
- **1-Byte XOR Auto-Deobfuscator**: Brute-force evaluates all 256 single-byte XOR keys against embedded buffers, automatically recovering hidden C2 URLs, PowerShell loaders, and shell scripts.
- **High-Entropy Section Slicing**: Identifies encrypted or compressed payloads within image carrier byte streams.
- **Polyglot Container Identification**: Detects `GIFAR`, `PNG-PHP`, `JPEG-PHP`, and `ZIP-Polyglots`.
- **Automated YARA Rule Generator (`--generate-yara`)**: Automatically compiles deployable `.yar` rules matching detected hashes, magic preambles, webshell patterns, and embedded payloads.

---

## 11. Visual OCR & Secret Credential Hunter (`lensint.modules.ocr_scan`)

Extracts text from images via Tesseract OCR and scans for confidential credentials and private keys:
- **Cloud & API Keys**: AWS Access Key IDs (`AKIA...`), GitHub Tokens (`ghp_...`, `github_pat_...`), OpenAI API Keys (`sk-...`), Slack Tokens (`xoxb-...`, `xoxp-...`).
- **Asymmetric Private Keys**: `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN OPENSSH PRIVATE KEY-----`.
- **Cleartext Passwords**: `password = "..."`, `api_secret = "..."`.
- **PII & Payment Data**: Credit Card numbers (validated via Luhn algorithm), Turkish TC Kimlik numbers, US Social Security Numbers (SSN).
- **Cryptocurrency Seed Phrases**: 12 and 24-word BIP39 mnemonic recovery phrases.

---

## 12. Strings Extraction & Threat Intelligence (`lensint.modules.strings_scan`, `lensint.modules.threat_intel`)

- **Dual-Encoding String Extraction**: Extracts contiguous ASCII and UTF-16LE strings meeting configurable length thresholds (`--min-string-len`).
- **IOC Pattern Matching**: Regex extraction of IPv4/IPv6 addresses, FQDNs, URLs, email addresses, Base64 blobs, and dangerous shell execution commands.
- **Threat Intelligence Correlation**: Formulates contextual query URLs for VirusTotal, Shodan, AbuseIPDB, and urlscan.io.

---

## 13. Neural AI & Deepfake Detection (`lensint.modules.neural_ai`, `lensint.modules.ai_detect`)

- **ONNX Runtime Deepfake Inference**: Executes local neural network models (`TruFor`, `CNNDetection`, Swin-Transformer) with strict SHA-256 hash manifest verification.
- **Academic Forensic Feature Layer**:
  - High-frequency Laplacian noise energy.
  - Spatial gradient curvature and smoothness ratios.
  - Inter-channel chrominance correlation ($r_{RG}$).
- **2D-FFT Spectral Peak Analysis**: Detects periodic grid spikes in the 2D frequency spectrum characteristic of GAN upsampling and diffusion generative models.
- **Prompt Injection Scanner**: Scans EXIF/PNG metadata and OCR text for adversarial LLM jailbreak vectors (`Ignore previous instructions`, `DAN mode`, persona overrides).

---

## 14. Volatile Memory Forensics & Volatility 3 Plugin (`lensint.modules.memory_forensics`, `lensint.volatility_plugin`)

- **RAM Dump Stream Carver (`--carve-memory`)**: Scans physical RAM dumps (`.raw`, `.dmp`, `.vmem`) to carve image buffers and memory textures with global hex offset attribution.
- **Official Volatility 3 Plugin (`windows.lensint_carve`)**: Traverses process Virtual Address Descriptors (VADs) and heap allocations to locate and carve uncommitted GDI/DIB surfaces and memory-resident C2 steganography carrier buffers.

---

## 15. EDR File Watcher & Dynamic Sandbox Ingestion (`lensint.modules.edr_sandbox`)

- **Real-Time Directory Watcher (`--watch-dir`)**: Monitors filesystem drop-zones in real-time, executing instant forensic audits on newly dropped files.
- **Dynamic Sandbox Ingestion (`--sandbox-dir`)**: Ingests automated malware sandbox run captures (CAPE / Cuckoo), correlates desktop screenshots, scans for leaked credentials, and generates a consolidated threat verdict.

---

## 16. Scientific Benchmark Harness & Bayesian Risk Fusion (`lensint.modules.benchmarks`)

- **`DatasetBenchmarkRunner`**: Ingests ground-truth labeled datasets (CASIA v2.0, CoMoFoD, BOSSBase, ForenSynths), computes Wilcoxon-Mann-Whitney ROC-AUC, Hanley-McNeil 95% Confidence Intervals, and calculates the optimal decision threshold via Youden's J statistic ($J = \text{TPR} - \text{FPR}$).
- **`BayesianForensicFusionEngine`**: Calibrates multi-modal evidence using context-specific operational priors ($P_0$), two-sided likelihood ratios, and correlation group attenuation ($1 / (1 + 1.5 \cdot c_g)$) to deliver an un-inflated posterior risk score.
