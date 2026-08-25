# Lensint: Image Forensics & Analysis Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-134%20passed-brightgreen.svg)](tests/)
[![Version](https://img.shields.io/badge/version-1.0.0-informational.svg)](pyproject.toml)

Lensint is an open-source Python framework for digital image forensics, metadata analysis, and heuristic threat detection. It provides a unified API and CLI for analyzing images for potential tampering, embedded data, and malicious payloads.

> **Note on Capabilities & Limitations:** Lensint relies primarily on statistical heuristics, signature matching, and classical computer vision techniques (e.g., ORB, ELA, OpenCV).
> - **Steganography:** The decoders (JSteg, F5, OutGuess) use statistical heuristics (like chi-square or LSB entropy) rather than true cryptographic parsing.
> - **Sandbox / Monitoring:** The memory/process monitoring relies on standard OS polling (e.g. os.walk, psutil) and does not use kernel-level drivers.
> - **Camera Signatures (DQT):** The included JPEG DQT profiles are estimated community samples.
> - **AI Models:** The framework supports loading external ONNX models for deepfake detection, but **no proprietary weights or models are included** in this repository.

## Features

- **Tampering Verification:** Error Level Analysis (ELA), Copy-Move forgery detection (ORB+RANSAC), JPEG Ghost detection.
- **Metadata & Provenance:** Parses EXIF, XMP, IPTC, and detects potential social media platform footprints.
- **Data Carving:** Extracts embedded files (ZIP, PDF, PHP, etc.) and analyzes polyglot file structures.
- **Volatility 3 Integration:** Includes a plugin to carve images directly from memory dumps.
- **OCR & Secret Scanning:** Uses Tesseract/EasyOCR (if installed) to extract text and uses regex to find potential API keys or credentials.
- **Reporting:** Generates output in JSON, HTML, and PDF formats.

## Installation

Lensint requires **ExifTool** and **FFmpeg** to be installed on your system path.

`ash
# Clone the repository
git clone https://github.com/yxdooo/lensint.git
cd lensint

# Install via pip
pip install -e .[cv,crypto,server]
`

## Usage

`ash
# Analyze a single image and generate an HTML report
lensint sample.jpg --html report.html

# Analyze an entire directory (Batch mode)
lensint ./evidence_folder --json results.json
`
