# Lensint: Digital Forensics & Threat Intelligence Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-1.0.0-informational.svg)](Cargo.toml)

Lensint is an open-source, highly performant, and memory-safe digital image forensics framework written entirely in pure Rust. It provides blazing-fast concurrent analysis of media files, deep structural anomaly detection, and embedded payload carving.

## Features (100% Pure Rust & Zero-Dependency)

- **Cryptographic Hashing:** Zero-copy MD5/SHA256 generation.
- **EXIF & Metadata Extraction:** Native metadata provenance verification.
- **Error Level Analysis (ELA):** Detects multiple compressions and spliced regions.
- **JPEG Ghost Detection:** Grid-based mathematical variance analysis to detect forged blocks.
- **Copy-Move Forgery Detection (CMFD):** Perceptual Block Hashing (aHash) to find cloned textures.
- **Steganography LSB Analyzer:** Shannon Entropy calculation to detect hidden AES payloads.
- **Data Carving:** Extracts embedded binary payloads/JPEGs from `.vmem`, `.dmp`, or `.pcap` files.
- **Custom AI Engine:** Native Multi-Layer Perceptron (MLP) calculating deepfake probabilities from high-frequency noise.
- **Structural OCR:** Pixel Projection Profiling and Sobel edge density to locate hidden text regions.
- **Threat Signatures:** High-speed Regex matching to detect PHP webshells, MZ headers, and JS injections.
- **HTML & JSON Reporting:** Native, zero-dependency report generation.

## Installation

```bash
# Clone the repository
git clone https://github.com/yxdooo/lensint.git
cd lensint

# Build the release binary
cargo build --release

# The executable will be available at target/release/lensint
```

## Usage

```bash
# Analyze a single image
lensint --target sample.jpg --output report.json

# Concurrently analyze an entire directory of evidence
lensint --target ./evidence_folder --output bulk_report.json
```
