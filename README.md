# Lensint: Image Forensics & Analysis Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-1.0.0-informational.svg)](Cargo.toml)

Lensint is an open-source, highly performant, and memory-safe digital image forensics framework written entirely in pure Rust. It provides blazing fast concurrent analysis of media files, cryptographic hashing, and metadata provenance verification.

## Architecture

Lensint 1.0 has been completely rewritten in Rust to meet industry standards for digital forensics:
- **Zero-Dependency Single Binary**: No need to configure Python environments or `pip` dependencies. Just run the executable.
- **Memory Safety**: Completely immune to classic buffer overflows and memory corruption exploits often used to hide malware in malformed images.
- **Extreme Concurrency**: Uses `rayon` to scale across all available CPU cores, enabling the analysis of thousands of images in seconds.
- **Bit-Level Integrity**: Evaluates files using zero-copy readers to generate provable SHA256/MD5 cryptographic hashes without mutating evidence.

## Installation

Make sure you have Rust and Cargo installed.

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
