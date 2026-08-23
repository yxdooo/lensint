# LENSINT System Architecture & Design

## Overview

**LENSINT** is built as a multi-stage, modular digital forensics and threat analysis pipeline. It is architected for both standalone CLI execution, high-throughput batch processing, and continuous REST API service in containerized DFIR/SOC environments.

```
                  +-----------------------------------+
                  |        Input Evidence File        |
                  |     (JPEG, PNG, WebP, GIF, etc.)  |
                  +-----------------+-----------------+
                                    |
            +-----------------------v-----------------------+
            |               ImageAnalyzer Entry             |
            |     (Decompression Bomb Guard / Caching)      |
            +-----------------------+-----------------------+
                                    |
        +---------------------------+---------------------------+
        |                           |                           |
+-------v-------+           +-------v-------+           +-------v-------+
|  1. Integrity |           |  2. Metadata  |           | 3. Tampering  |
|  Magic Bytes  |           |  EXIF / GPS   |           | Multi-Scale   |
|  Hash Engine  |           |  Reverse Geo  |           | ELA / Splicing|
|  (MD5/SHA256) |           |  XMP / IPTC   |           | Copy-Move DCT |
+-------+-------+           +-------+-------+           +-------+-------+
        |                           |                           |
+-------v-------+           +-------v-------+           +-------v-------+
| 4. Stego &    |           | 5. AI / Deep- |           | 6. Strings &  |
|   Payloads    |           |    fake       |           |    IOCs       |
| RS Stego / EOF|           | 2D FFT / PRNU |           | Threat Intel  |
| Bit-Planes    |           | Inpainting    |           | VirusTotal/IP |
+-------+-------+           +-------+-------+           +-------+-------+
        |                           |                           |
        +---------------------------+---------------------------+
                                    |
                    +---------------v---------------+
                    |     Verdict Scoring Engine    |
                    |     (CRITICAL, HIGH, etc.)    |
                    +---------------+---------------+
                                    |
                    +---------------v---------------+
                    |  Forensic Audit & Custody     |
                    |  (Cryptographically Sealed)   |
                    +---------------+---------------+
                                    |
            +-----------------------+-----------------------+
            |                       |                       |
    +-------v-------+       +-------v-------+       +-------v-------+
    |  Rich Console |       |  HTML/JSON    |       |    STIX 2.1   |
    |  Terminal UI  |       |  Reports      |       |  Threat Bundle|
    +---------------+       +---------------+       +---------------+
```

---

## Key Architectural Principles

1. **Thread-Safe Memory Isolation**:
   - Each worker thread in `analyzer.py` operates on a deep copy of the image and byte stream to prevent race conditions during concurrent multi-threaded forensic scans.

2. **DoS & Decompression Bomb Protection**:
   - Files are validated against `MAX_IMAGE_PIXELS` (128 Megapixels) and safely downsampled before memory allocation if excessive dimensions are encountered.

3. **High-Performance SHA-256 Caching**:
   - Analysis results are cryptographically indexed by SHA-256 in `lensint/cache.py` with automatic TTL-based disk expiration.

4. **Tamper-Evident Chain of Custody**:
   - Every execution produces a canonical JSON record with an embedded SHA-256 audit seal for courtroom admissibility (`lensint/audit.py`).
