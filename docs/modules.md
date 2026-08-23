# LENSINT Forensic & Security Modules Reference

Comprehensive guide to all analytical, mathematical, threat hunting, and memory forensics modules in LENSINT v3.5.

---

## 1. File Structure & Cryptographic Integrity (`modules/integrity.py`)

- **Magic Byte Validation**: Direct inspection of the container preamble bytes (`FF D8 FF` for JPEG, `89 50 4E 47 0D 0A 1A 0A` for PNG, `47 49 46 38` for GIF, `52 49 46 46 ... 57 45 42 50` for WebP, `42 4D` for BMP, `49 49` / `4D 4D` for TIFF).
- **Extension Spoofing**: Detects scripts (PHP, JS, Python, Bash) or executable binaries (PE/ELF) renamed with `.jpg`, `.png`, or `.gif` extensions.
- **Cryptographic Fingerprinting**: Computes MD5, SHA-1, SHA-256, and SHA-512 hashes simultaneously.
- **Screenshot / Capture Contextualizer**: Recognizes native mobile (iOS, Android) and desktop (macOS, Windows, Linux) screenshot naming conventions, dimensions, and color profiles to contextualize sensor noise heuristics.

---

## 2. Metadata, OSINT & Footprinting (`modules/metadata.py`)

- **EXIF IFD Engine**: Extracts make, model, software, serial numbers, lens specifications, exposure, aperture, and ISO settings.
- **Reverse Geocoding**: Queries OpenStreetMap Nominatim for GPS coordinates ($lat, lon \to \text{physical street address}$).
- **Social Media Provenance Classifier**: Identifies compression and metadata-stripping fingerprints characteristic of WhatsApp, Telegram, Twitter/X, and Instagram.
- **Thumbnail SSIM Verification**: Computes the Structural Similarity Index Measure (SSIM) between the embedded EXIF thumbnail and the downsampled main image to flag selective retouching.
- **Temporal Chronology Anomaly**: Detects clock forgery (ModifyDate precedes DateTimeOriginal, future dates, GPS vs EXIF drift).
- **XMP & IPTC Parsing**: Extracts Dublin Core, Adobe Photoshop History trails, and IPTC press/byline datasets.

---

## 3. Courtroom-Grade Tampering Forensics (`modules/tampering.py`)

1. **Multi-Scale Error Level Analysis (ELA)**: Evaluates compression difference across calibrated JPEG qualities ($Q \in \{70, 80, 90\}$).
2. **Splice & Noise Inconsistency Detection**: Maps block-wise high-pass Laplacian noise variance to identify foreign spliced fragments.
3. **Copy-Move (Cloning) Detection**: Utilizes ORB keypoint descriptor clustering and Euclidean spatial thresholding to flag duplicate image regions.
4. **JPEG Ghost Analysis**: Recompresses across $Q \in [50..95]$ to pinpoint spliced elements from images with different compression histories.
5. **DQT Quantization Forensics**: Matches $8\times8$ quantization tables against hardware cameras (iPhone 11-16 Pro, Galaxy S20-S24 Ultra, Pixel 6-9 Pro, Canon, Nikon, Sony, DJI Drones) and desktop editing software (Photoshop, Lightroom, GIMP).
6. **CFA Bayer Demosaicing**: Detects disruptions in camera sensor color interpolation grids.
7. **8x8 DCT Block Grid Shift**: Identifies pasted patches misaligned with the global 8x8 DCT grid phase.
8. **Chromatic Aberration Vectors**: Analyzes radial optical convergence to detect composite objects shot on different lenses.
9. **Median Filter Smoothing**: Detects anti-forensic post-processing used to conceal edit seams.
10. **Illumination Angle Consistency**: Circular statistics ($\text{atan2}$) surface normal lighting vector evaluation across image quadrants.

---

## 4. Steganography, LSB Carver & Palet Analysis (`modules/stego.py`, `modules/stego_extract.py`)

- **Trailing Overlay Detection & Carver**: Identifies and extracts data hidden past container End-of-File (EOF) markers (`--extract-overlay`).
- **Vectorized LSB File Carver**: Fast `np.packbits` extraction carving embedded `ZIP`, `PNG`, `PDF`, `EXE`, `ELF`, and `7z` files.
- **Palette Steganalysis**: Detects micro-variant parity modulations in indexed color tables (PNG/GIF).
- **Stego Wordlist Dictionary Attack**: Tests carriers against standard steganography passphrases.
- **RS (Regular/Singular) Steganalysis**: Quantifies LSB replacement by applying flipping masks and calculating sample variance variation.

---

## 5. Malware, WebShells & YARA Rules (`modules/malware_rules.py`)

- **Native YARA Scanning**: Detects generic PHP WebShells, Cobalt Strike stagers, Reverse Shells, and PE headers.
- **Auto-Deobfuscator**: 1-Byte XOR brute-force scanner automatically decoding hidden C2 URLs, PowerShell loaders, and shell commands.
- **High-Entropy Section Slicing**: Flags encrypted/compressed payloads.
- **Polyglot Containers**: Identifies `GIFAR`, `PNG-PHP`, `JPEG-PHP`, and `ZIP-Polyglots`.

---

## 6. OCR & Confidential Secret Leak Hunter (`modules/ocr_scan.py`)

- **Credential Scanner**: Extracts text from visual elements and scans for:
  - AWS Access Keys (`AKIA...`) & Secret Access Keys
  - GitHub Tokens (`ghp_...`, `github_pat_...`)
  - OpenAI Secret Keys (`sk-...`)
  - Slack API Tokens (`xoxb-...`, `xoxp-...`)
  - Asymmetric Private Keys (`BEGIN RSA/OPENSSH PRIVATE KEY`)
  - Cleartext Passwords (`password = "..."`)
  - Credit Cards (Luhn validated), TC Kimlik, US SSN
  - 12/24 word BIP39 Cryptocurrency Seed Recovery Phrases

---

## 7. Memory Forensics & Volatility 3 Plugin (`modules/memory_forensics.py`)

- **RAM Dump Carver (`--carve-memory`)**: Stream-carves image allocations and textures from volatile memory dumps (`.raw`, `.dmp`, `.vmem`).
- **Volatility 3 Integration (`VolatilityLensintPlugin`)**: Allows direct kernel layer and process heap scanning inside Volatility 3.

---

## 8. C2 Steganography & Covert Channels (`modules/c2_stego_decoders.py`)

- **DCT Frequency Stego Decoders**: Detects JSteg, JPHide, F5 Matrix Embedding, OutGuess 0.2, and Hide4PGP carriers.
- **PNG Covert Channels**: Detects CRC32 checksum covert channels, anomalous custom chunks (`coVT`, `stEG`), and `zTXt`/`iTXt` hidden compression tunnels.

---

## 9. Neural AI & Deepfake Detection (`modules/neural_ai.py`)

- **ONNX Deepfake Inference Pipeline**: Runs neural synthetic image detection models (`TruFor`, `CNNDetection`).
- **Diffusion Prompt Injection Hunter**: Detects jailbreak vectors (`"Ignore previous instructions"`, `"DAN Mode"`) concealed in metadata or OCR text.

---

## 10. Kernel-Level EDR & Sandbox Ingestion (`modules/edr_sandbox.py`)

- **EDR Real-Time File Drop Monitor (`--watch-dir`)**: Watches filesystem directories in real-time and audits newly dropped evidence files instantly.
- **CAPE / Cuckoo Sandbox Ingestion (`--sandbox-dir`)**: Ingests automated malware sandbox run captures, correlates desktop screenshots, scans for leaked credentials, and produces a consolidated threat verdict.
