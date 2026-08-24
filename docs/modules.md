# LENSINT Forensic & Security Modules Reference Guide

## Overview

This technical specification provides an exhaustive breakdown of every analytical engine, mathematical algorithm, structural parser, network carver, and threat hunting module within LENSINT.

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
- **Digital Screen Capture Contextualizer**: Evaluates file naming conventions, fixed screen dimensions (macOS Retina, Windows, iOS, Android), and sRGB color profiles. When an image is identified as a digital screen capture, camera sensor heuristics (PRNU, CFA demosaicing, sensor dust) are automatically contextualized to suppress false positives.

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

## 4. C2PA & JUMBF Content Provenance Manifest Forensics (`lensint.modules.c2pa_manifest`)

Comprehensive extraction and cryptographic verification of Coalition for Content Provenance and Authenticity (C2PA) and ISO/IEC 19566-5 JUMBF (JPEG Universal Metadata Box Format) manifests.

- **ISO/IEC 19566-5 JUMBF Container Parser**: Recursively parses superbox structures across image formats:
  - JPEG: APP11 segments (`0xFFEB`) prefixed with `JP\x00\x00` or `JUMBF\x00`.
  - PNG: `caP1`, `c2pa`, and `jumb` ancillary chunks.
  - WebP: `c2pa` RIFF four-character code chunks.
  - Box Types: `jumb` (Superbox container), `jumd` (Description box with UUID and labels), `c2pa.manifest_store`, `c2pa.assertion_store` (`c2as`), `c2pa.claim_signature` (`c2cs`), `c2pa.claim` (`c2cl`), and `c2pa.thumbnail` (`c2th`).
- **CBOR (RFC 8949) Decoding Engine**: High-performance Concise Binary Object Representation parser featuring `PureCBORDecoder` fallback for zero-dependency parsing of maps, byte strings, tagged elements, and IEEE 754 half/single/double precision floats.
- **COSE Sign1 (RFC 9052) Cryptographic Verification**: Extracts and parses protected headers, unprotected attributes (`x5chain`, `sigT`), and raw signature bytes across signature algorithms:
  - `ES256` (ECDSA P-256 / SHA-256)
  - `ES384` (ECDSA P-384 / SHA-384)
  - `ES512` (ECDSA P-521 / SHA-512)
  - `PS256` / `PS384` / `PS512` (RSA-PSS with SHA-256/384/512)
  - `Ed25519` (EdDSA using Curve25519)
  - `RS256` (RSASSA-PKCS1-v1_5)
- **X.509 Certificate Chain Analysis**: Evaluates DER-encoded certificate chains (`parse_x509_der_cert`), checking validity timestamps against current UTC time, serial numbers, Subject/Issuer Common Names and Organizations, and public key bit lengths.
- **Provenance History & Generative AI Actions**: Traverses `c2pa.actions` assertions to trace chronological edit history, software agents, parameters, and flags declared synthetic media creation (`digitalSourceType: trainedAlgorithmicMedia` / `c2pa.created`).
- **Asset Binding Hash Verification**: Calculates the SHA-256 digest of clean image byte ranges excluding JUMBF metadata boundaries and compares against the manifest's declared `c2pa.hash.data` binding assertion.
- **Anti-Forensics Manifest Stripping Detection**: Detects anti-forensic deletion where C2PA/CAI provenance namespaces (`xmlns:c2pa=`, `c2pa:manifest`, `cai:claim`) persist in XMP/EXIF blocks but binary JUMBF containers have been removed.

---

## 5. Biometric rPPG & Video Deepfake Forensics (`lensint.modules.biometrics_rppg`)

Extracts physiological cardiovascular blood volume pulse (BVP) waveforms from facial video streams and validates human biological consistency to uncover deepfakes and AI face swaps.

- **Skin ROI Segmentation**: Models skin chrominance using ITU-R BT.601 YCbCr biometric constraints ($Y \ge 40, 77 \le C_b \le 127, 133 \le C_r \le 173$) across Forehead, Left Cheek, and Right Cheek sub-regions.
- **CHROM (Chrominance-Based) Pulse Extraction**: Decomposes normalized color signals $R_n, G_n, B_n$ into orthogonal chrominance vectors:
  $$X_s = 3 R_n - 2 G_n, \quad Y_s = 1.5 R_n + G_n - 1.5 B_n$$
  $$\alpha = \frac{\sigma(X_s)}{\sigma(Y_s)}, \quad S_{\text{CHROM}} = X_s - \alpha Y_s$$
- **POS (Plane-Orthogonal-to-Skin) Pulse Extraction**: Projects normalized color signals onto a plane orthogonal to the skin tone reflection vector:
  $$P_1 = G_n - B_n, \quad P_2 = -2 R_n + G_n + B_n$$
  $$\alpha = \frac{\sigma(P_1)}{\sigma(P_2)}, \quad S_{\text{POS}} = P_1 + \alpha P_2$$
- **Zero-Phase Butterworth Bandpass Filter**: Isolates human cardiovascular frequencies in the envelope $[0.7\text{ Hz}, 3.5\text{ Hz}]$ ($42 - 210\text{ BPM}$) using frequency-domain FFT masking with smooth Tukey window transitions.
- **Power Spectral Density (PSD) & Signal-to-Noise Ratio (SNR)**: Computes dominant pulse frequency $f_{\text{peak}}$, heart rate in BPM, spectral entropy, and SNR in decibels:
  $$\text{SNR} = 10 \log_{10}\left( \frac{P(f_{\text{peak}} \pm 0.15) + P(2 f_{\text{peak}} \pm 0.15)}{P_{\text{noise}}} \right)$$
- **Cross-Region Facial Phase Coherence**: Evaluates correlation coefficients across forehead, left cheek, and right cheek pulses. Natural biological flow exhibits synchronized phase ($\text{coherence} > 0.65$); synthetic face replacements exhibit regional phase desynchronization ($\text{coherence} < 0.35$).
- **Eye Aspect Ratio (EAR) Poisson Blink Dynamics**: Tracks eye aperture ratio over time, identifies blink dips ($\text{EAR} < 0.20$), and models Inter-Blink Intervals (IBI) against a Poisson point process ($\text{IBI} \sim \text{Exp}(\lambda)$). Flags synthetic artifacts including periodic blinking, erratic flicker, and blink suppression.
- **3D Corneal Specular Reflection Disparity**: Quantifies relative offset disparity between pupil centers and specular glints in both eyes to detect synthetic lighting inconsistencies.

---

## 6. Sensor Dust Invariant Mapping & Optical Lens Forensics (`lensint.modules.optics_dust`)

Physical camera ballistics and optical distortion profiling for device attribution and synthetic imagery classification.

- **Sensor Dust Invariant Mapping**: Models stationary dust specks and scratches on the sensor cover glass as optical attenuation filters:
  $$I_{\text{obs}}(x, y) = I_{\text{scene}}(x, y) \cdot (1 - \Delta(x, y))$$
- **Multi-Scale Laplacian of Gaussian (LoG) Filter Bank**: Employs spatial LoG kernels ($\sigma \in \{1.8, 2.8, 4.2\}$) with zero-DC response normalization to extract subtle circular intensity dips while suppressing high-gradient scene textures via Sobel edge masking.
- **Microscopic Dust Speck Metrics**: Measures optical depth $\Delta$, contrast, radius, and circularity for each detected dust artifact.
- **Bipartite Matching Camera Ballistics (1:1 & 1:N)**: Evaluates 1:1 camera source verification between two images using minimum-weight bipartite matching and Poisson Point Process coincidence statistics. The False Alarm Probability is computed as:
  $$P_{\text{FA}} = 1 - \sum_{i=0}^{k-1} \frac{\lambda^i e^{-\lambda}}{i!}, \quad \lambda = N_A N_B \frac{\pi r_{\text{tol}}^2}{A_{\text{sensor}}}$$
  Alignments with $k \ge 5$ matched spots achieve definitive device matching ($P_{\text{FA}} < 10^{-5}$).
- **Spatial Dust Fingerprint Hash**: Compiles detected speck spatial coordinates and confidence scores into a 256-bit SHA-256 spatial grid hash.
- **Brown-Conrady Lens Distortion Profiling**: Fits radial ($k_1, k_2$) and tangential ($p_1, p_2$) distortion parameters to evaluate straight-line curvature:
  $$x_u = x_d + (x_d - x_c)(k_1 r^2 + k_2 r^4) + [p_1(r^2 + 2(x_d - x_c)^2) + 2 p_2(x_d - x_c)(y_d - y_c)]$$
  $$y_u = y_d + (y_d - y_c)(k_1 r^2 + k_2 r^4) + [p_2(r^2 + 2(y_d - y_c)^2) + 2 p_1(x_d - x_c)(y_d - y_c)]$$
  Distinguishes real physical lens curvature (Barrel, Pincushion, Mustache) from rectilinear zero-distortion synthetic CGI and AI-generated imagery.

---

## 7. Spatial Rich Model (SRM) & Modern Content-Adaptive Steganalysis (`lensint.modules.neural_stego`)

High-order spatial residual filter banks and statistical modeling for modern content-adaptive steganography.

- **Spatial Rich Model (SRM) 30 Sub-Model Filter Bank**: Implements the complete SRM architecture (Fridrich & Kodovsky):
  - 1st-Order Derivatives: Horizontal, Vertical, Diagonal, Anti-diagonal.
  - 2nd-Order Derivatives: Horizontal, Vertical, Diagonal, Anti-diagonal.
  - 3rd-Order Derivatives: Horizontal, Vertical, Diagonal, Anti-diagonal.
  - 3x3 Edge, Corner, Laplacian, and Diagonal Laplacian kernels.
  - 5x5 Square and 5x5 Laplacian high-order models.
  - Non-linear min/max filter pairs: $\min(1\text{st}), \max(1\text{st}), \min(2\text{nd}), \max(2\text{nd}), \min(\text{edge}), \max(\text{edge})$.
- **4D Co-occurrence Probability Statistics**: Evaluates quantized and truncated residuals $r_{\text{quant}} = \text{clip}(\text{round}(r / q), -T, T)$ with $q=1.5, T=2$. Measures transition probability entropy and kurtosis across adjacent residual samples.
- **Content-Adaptive Steganography Detection**: Detects modern adaptive spatial algorithms (S-UNIWARD, WOW, HILL, MiPOD) that embed payloads selectively into complex texture regions to evade standard LSB scanners.
- **Steghide Graph-Pair Symmetry Break**: Detects Steghide graph-theoretic parity matching by analyzing histogram Pairs of Values (PoV) convergence ($2k \leftrightarrow 2k+1$) and unnatural symmetry equalization.
- **OpenPuff Multi-Carrier Scanner**: Evaluates 8-bitplane Shannon entropy uniformity ($H \ge 0.9996$) and lag-1 spatial autocorrelation flatness across RGB channels.
- **Payload Capacity & bpp Estimation**: Estimates embedding rate in bits per pixel (bpp) and calculates total hidden payload bytes.

---

## 8. Live Network PCAP/PCAPNG Packet Parser & Multimedia Carver (`lensint.modules.pcap_stream`)

Deep packet inspection (DPI), stateful TCP conversation stream reassembly, and automated multimedia carving.

- **PCAP / PCAPNG Container Decoding**: Ingests classic microsecond/nanosecond PCAP and PCAPNG Section Header Blocks (SHB), Interface Description Blocks (IDB), and Enhanced Packet Blocks (EPB).
- **Multi-Layer Protocol Decoders**: Decodes Ethernet II, 802.1Q VLAN, IPv4, IPv6, TCP, and UDP layers.
- **TCP Stream Reassembly State Machine**: Tracks bidirectional 4-tuple connections, reassembles ordered packet sequences, resolves segment overlaps, and deduplicates retransmissions.
- **Application Protocol Decoders**:
  - HTTP/1.1 & HTTP/2: Reassembles HTTP response bodies, dechunks `Transfer-Encoding: chunked` streams, parses `Content-Type: multipart/form-data` MIME upload boundaries, and extracts transmitted images and videos.
  - SMB2 / SMB3: Parses Server Message Block file transfers over port 445, carving media buffers from SMB2 File Read Responses (`0x0008`) and Write Requests (`0x0009`).
  - Deep Raw Stream Carving: Scans raw TCP conversation payloads for magic header and EOF boundaries (JPEG `FF D8 FF` ... `FF D9`, PNG `89 50 4E 47` ... `IEND`, GIF `GIF87a`/`GIF89a`, WebP `RIFF...WEBP`, BMP `BM`, MP4 `ftyp`).
- **CLI Integration (`--pcap`)**: Ingests `.pcap` and `.pcapng` capture files, outputs conversation summaries, and exports carved visual evidence to designated directories.

---

## 9. Camera Sensor PRNU Device Identification & 1:N Matching (`lensint.modules.prnu`)

Identifies individual physical camera hardware devices based on sensor silicon imperfections.

- **Adaptive Spatial Wiener Noise Residual**: Isolates sensor noise $W = I - F(I)$ via local adaptive 2D Wiener filtering with robust MAD noise variance estimation ($\sigma_0^2$).
- **Linear Artifact Suppression**: Subtracts horizontal and vertical mean vectors to eliminate CMOS readout lines and JPEG block artifacts.
- **Peak-to-Correlation Energy (PCE)**: 2D-FFT circular cross-correlation between noise residual $W$ and candidate sensor fingerprint $K$. PCE values $\ge 60.0$ yield theoretical False Alarm Rates $\text{FAR} < 10^{-6}$.
- **Maximum Likelihood Estimation (MLE) Fingerprint Synthesis**: Combines multiple flat calibration images to generate a clean camera sensor model:
  $$\hat{K} = \frac{\sum_i W_i \odot I_i}{\sum_i I_i^2}$$
- **1:N Suspect Camera Database (`PRNUDatabase`)**: Matches unknown visual evidence against registered suspect hardware camera profiles.

---

## 10. Meta PDQ 256-Bit Perceptual Hashing & BK-Tree Triage (`lensint.modules.pdq_hash`)

Perceptual image fingerprinting compliant with open industry standards for threat triage and illicit content matching.

- **256-Bit Perceptual Hashing**: Preprocesses image to $64 \times 64$ with Jarosz domain Box Blur, projects spatial matrix through an orthonormal $16 \times 64$ 2D-DCT basis matrix, and generates 256 binary bits via AC median thresholding.
- **Burkhard-Keller Metric Tree (`BKTreePDQIndex`)**: Indexes millions of 256-bit perceptual hashes in metric space, executing sub-millisecond similarity range queries ($D_H \le 31$) using triangle inequality distance pruning:
  $$|d(u, q) - d(u, v)| \le r$$
- **Zero-Knowledge Forensic Triage**: Enables automated threat correlation against known illicit media repositories without displaying sensitive visual imagery on screen.

---

## 11. Video Forensics, ISOBMFF Parsing & GOP Cadence (`lensint.modules.video_forensics`)

Structural container and temporal GOP splicing analysis for digital video containers.

- **ISOBMFF Container Box Hierarchy**: Parses MP4, MOV, MKV, and AVI atom box trees (`ftyp`, `moov`, `mdat`, `trak`, `udta`).
- **Trailing Video Overlay Carving**: Detects and extracts hidden data and C2 steganographic payloads appended past the `mdat` container boundary.
- **Editing Software Footprints**: Flags editing signatures from Adobe Premiere Pro, DaVinci Resolve, Apple Final Cut Pro, FFmpeg (`Lavf`/`Lavc`), HandBrake, CapCut, and Camtasia.
- **NAL Unit & Temporal GOP Splicing Analysis**: Scans Annex B and AVCC bitstreams (I/P/B frames). Evaluates keyframe spacing consistency; flags temporal video cutting/splicing when GOP standard deviation exceeds threshold ($\sigma_{GOP} > 4.0$).

---

## 12. Pure-Python Baseline JPEG DCT Engine (`lensint.modules.jpeg_dct`)

Low-level pure-Python bitstream parser for Baseline Sequential JPEGs (SOF0).

- **Huffman Table Construction**: Constructs DC and AC Huffman lookup tables from DHT segments (`0xFFC4`).
- **Restart Marker Synchronization (DRI / RST0-RST7)**: Accurately handles Define Restart Interval markers (`0xFFDD`). Discards leftover sub-byte bits upon RST markers (`0xFFD0`–`0xFFD7`), aligns to the byte boundary, and resets DC predictors to zero.
- **Scan Header Decoding**: Supports multi-scan and multi-SOS sequential data decoding without external C library dependencies.

---

## 13. Classical C2 Steganography & Frequency Decoders (`lensint.modules.c2_stego_decoders`)

Analytical decoders designed for Command and Control (C2) threat hunting.

- **JSteg DCT Payload Extractor**: Extracts LSB bits embedded in non-zero AC DCT coefficients ($\neq 0, \pm 1$). Computes Shannon entropy and identifies embedded file headers (`PK\x03\x04`, `MZ`, `ELF`, `PDF`).
- **F5 Matrix Embedding Analyzer**: Evaluates $(1, 2^k - 1, k)$ matrix embedding capacity from non-zero AC coefficients and quantifies histogram shrinkage.
- **OutGuess 0.2 Histogram Symmetry Analyzer**: Quantifies histogram symmetry preservation anomalies across Pairs of Values (PoVs).
- **Westfeld Chi-Square ($\chi^2$) Analysis**: Applies goodness-of-fit testing on PoV frequencies to detect LSB replacement:
  $$\chi^2 = \sum_{k=1}^m \frac{(y_{2k} - y_{2k}^*)^2}{y_{2k}^*}, \quad y_{2k}^* = \frac{y_{2k} + y_{2k+1}}{2}$$
- **Calibrated RS Steganalysis**: Applies dual inversion flipping masks to quantify regular and singular group count variations, with texture-variance gating ($0.08$) to eliminate false alarms on flat surfaces.
- **PNG Structural Anomaly Inspection**: Validates IHDR length (strictly 13 bytes) and color type/bit depth compatibility, checks CRC32 checksums, detects IDAT chunk sequence fragmentation, flags unregistered ancillary chunks, and decompresses `zTXt`/`iTXt` metadata tunnels.

---

## 14. Malware, WebShells & YARA Rule Generator (`lensint.modules.malware_rules`, `lensint.reporters.yara_gen`)

- **Static YARA Threat Scanner**: Scans media payloads for generic PHP webshells (`eval(base64_decode(...))`, `passthru`, `system`), Cobalt Strike stagers, reverse shells, and PE header signatures.
- **1-Byte XOR Auto-Deobfuscator**: Brute-force evaluates all 256 single-byte XOR keys against embedded buffers, automatically recovering hidden C2 URLs, PowerShell loaders, and shell scripts.
- **High-Entropy Section Slicing**: Identifies encrypted or compressed payloads within image carrier byte streams.
- **Polyglot Container Identification**: Detects `GIFAR`, `PNG-PHP`, `JPEG-PHP`, and `ZIP-Polyglots`.
- **Automated YARA Rule Generator (`--generate-yara`)**: Automatically compiles deployable `.yar` rules matching detected hashes, magic preambles, webshell patterns, and embedded payloads.

---

## 15. Visual OCR & Secret Credential Hunter (`lensint.modules.ocr_scan`)

Extracts text from images via Tesseract OCR and scans for confidential credentials and private keys:
- **Cloud & API Keys**: AWS Access Key IDs (`AKIA...`), GitHub Tokens (`ghp_...`, `github_pat_...`), OpenAI API Keys (`sk-...`), Slack Tokens (`xoxb-...`, `xoxp-...`).
- **Asymmetric Private Keys**: `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN OPENSSH PRIVATE KEY-----`.
- **Cleartext Passwords**: `password = "..."`, `api_secret = "..."`.
- **PII & Payment Data**: Credit Card numbers (validated via Luhn algorithm), Turkish TC Kimlik numbers, US Social Security Numbers (SSN).
- **Cryptocurrency Seed Phrases**: 12 and 24-word BIP39 mnemonic recovery phrases.

---

## 16. Strings Extraction & Threat Intelligence (`lensint.modules.strings_scan`, `lensint.modules.threat_intel`)

- **Dual-Encoding String Extraction**: Extracts contiguous ASCII and UTF-16LE strings meeting configurable length thresholds (`--min-string-len`).
- **IOC Pattern Matching**: Regex extraction of IPv4/IPv6 addresses, FQDNs, URLs, email addresses, Base64 blobs, and dangerous shell execution commands.
- **Threat Intelligence Correlation**: Formulates contextual query URLs for VirusTotal, Shodan, AbuseIPDB, and urlscan.io.

---

## 17. Neural AI & Deepfake Detection (`lensint.modules.neural_ai`, `lensint.modules.ai_detect`)

- **ONNX Runtime Deepfake Inference**: Executes local neural network models (`TruFor`, `CNNDetection`, Swin-Transformer) with strict SHA-256 hash manifest verification.
- **Academic Forensic Feature Layer**:
  - High-frequency Laplacian noise energy.
  - Spatial gradient curvature and smoothness ratios.
  - Inter-channel chrominance correlation ($r_{RG}$).
- **2D-FFT Spectral Peak Analysis**: Detects periodic grid spikes in the 2D frequency spectrum characteristic of GAN upsampling and diffusion generative models.
- **Prompt Injection Scanner**: Scans EXIF/PNG metadata and OCR text for adversarial LLM jailbreak vectors (`Ignore previous instructions`, `DAN mode`, persona overrides).

---

## 18. Volatile Memory Forensics & Volatility 3 Plugin (`lensint.modules.memory_forensics`, `lensint.volatility_plugin`)

- **RAM Dump Stream Carver (`--carve-memory`)**: Scans physical RAM dumps (`.raw`, `.dmp`, `.vmem`) to carve image buffers and memory textures with global hex offset attribution.
- **Official Volatility 3 Plugin (`windows.lensint_carve`)**: Traverses process Virtual Address Descriptors (VADs) and heap allocations to locate and carve uncommitted GDI/DIB surfaces and memory-resident C2 steganography carrier buffers.

---

## 19. EDR File Watcher & Dynamic Sandbox Ingestion (`lensint.modules.edr_sandbox`)

- **Real-Time Directory Watcher (`--watch-dir`)**: Monitors filesystem drop-zones in real-time, executing instant forensic audits on newly dropped files.
- **Dynamic Sandbox Ingestion (`--sandbox-dir`)**: Ingests automated malware sandbox run captures (CAPE / Cuckoo), correlates desktop screenshots, scans for leaked credentials, and generates a consolidated threat verdict.

---

## 20. Scientific Benchmark Harness & Bayesian Risk Fusion (`lensint.modules.benchmarks`)

- **`DatasetBenchmarkRunner`**: Ingests ground-truth labeled datasets (CASIA v2.0, CoMoFoD, BOSSBase, ForenSynths), computes Wilcoxon-Mann-Whitney ROC-AUC, Hanley-McNeil 95% Confidence Intervals, and calculates the optimal decision threshold via Youden's J statistic ($J = \text{TPR} - \text{FPR}$).
- **`BayesianForensicFusionEngine`**: Calibrates multi-modal evidence using context-specific operational priors ($P_0$), two-sided likelihood ratios, and correlation group attenuation ($1 / (1 + 1.5 \cdot c_g)$) to deliver an un-inflated posterior risk score.
