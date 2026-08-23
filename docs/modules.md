# LENSINT Forensic & Security Modules Reference

Comprehensive guide to all analytical, mathematical, and threat hunting modules in LENSINT.

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
5. **DQT Quantization Forensics**: Matches $8\times8$ quantization tables against hardware cameras and desktop editing software (Photoshop, GIMP).
6. **CFA Bayer Demosaicing**: Detects disruptions in camera sensor color interpolation grids.
7. **8x8 DCT Block Grid Shift**: Identifies pasted patches misaligned with the global 8x8 DCT grid phase.
8. **Chromatic Aberration Vectors**: Analyzes radial optical convergence to detect composite objects shot on different lenses.
9. **Median Filter Smoothing**: Detects anti-forensic post-processing used to conceal edit seams.
10. **Illumination Angle Consistency**: Measures surface normal lighting vectors across image quadrants.

---

## 4. Steganography & Payload Extraction (`modules/stego.py`)

- **Trailing Overlay Detection**: Identifies and extracts data hidden past container End-of-File (EOF) markers.
- **RS (Regular/Singular) Steganalysis**: Quantifies LSB replacement by applying flipping masks and calculating sample variance variation.
- **Tool Signature Matching**: Built-in rules for OpenStego, SilentEye, JPHide, StegHide, and F5.
- **3-Channel LSB Shannon Entropy**: Computes Shannon entropy across R, G, B, and interleaved bitstreams ($H \in [0.0..8.0]$).
- **Bit-Plane Slicing**: Visualizes Plane 0 (LSB) through Plane 7 (MSB).

---

## 5. Malware, WebShells & YARA Rules (`modules/malware_rules.py`)

- **Native YARA Scanning**: Detects generic PHP WebShells, Cobalt Strike stagers, Reverse Shells, and PE headers.
- **Auto-Deobfuscator**: 1-Byte XOR brute-force scanner automatically decoding hidden C2 URLs, PowerShell loaders, and shell commands.
- **High-Entropy Section Slicing**: Flags encrypted/compressed payloads (Entropy > 7.5).
- **Polyglot Containers**: Identifies `GIFAR`, `PNG-PHP`, `JPEG-PHP`, and `ZIP-Polyglots`.

---

## 6. Threat Intelligence & OSINT (`modules/threat_intel.py`)

- Direct IOC correlation with VirusTotal, Shodan, AbuseIPDB, HybridAnalysis, and ThreatFox.
- Reverse image search query links for Google Lens, Bing Visual Search, Yandex, and TinEye.
