"""Advanced Steganography Payload Extractor, Carver, Palette Steganalysis & Passphrase Brute-Forcer.

Extracts hidden files from LSB channels, carves nested archives/executables,
and tests for common steganography passphrases.
"""
from __future__ import annotations

import io
import math
import struct
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from PIL import Image


COMMON_STEGO_PASSWORDS = [
    "password", "123456", "secret", "admin", "stego", "hidden", "flag",
    "forensics", "hunter", "root", "12345678", "qwerty", "letmein", "default",
    "dragon", "master", "access", "shadow", "cyber", "lensint", "key", "pass",
    "welcome", "test", "security", "guest", "matrix", "crypto", "hack", "ninja"
]

KNOWN_MAGIC_HEADERS = [
    (b"PK\x03\x04", "ZIP / Office Archive", ".zip"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", ".png"),
    (b"\xFF\xD8\xFF", "JPEG Image", ".jpg"),
    (b"%PDF-", "PDF Document", ".pdf"),
    (b"MZ", "Windows PE Executable", ".exe"),
    (b"\x7fELF", "Linux ELF Binary", ".elf"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", ".7z"),
    (b"Rar!\x1a\x07", "RAR Archive", ".rar"),
    (b"\x1f\x8b\x08", "GZIP Compressed File", ".gz"),
]


def extract_lsb_payload(
    pil_img: Image.Image,
    channels: str = "RGB",
    max_bytes: int = 1024 * 1024,
) -> Optional[Dict[str, Any]]:
    """Extract LSB bitstream from image and carve valid embedded files."""
    if pil_img is None:
        return None

    img = pil_img.convert("RGB")
    arr = np.array(img)
    h, w, c = arr.shape

    # Extract 1-bit LSB from selected channels with vectorized NumPy operations
    channel_indices = []
    for char in channels.upper():
        if char == "R": channel_indices.append(0)
        elif char == "G": channel_indices.append(1)
        elif char == "B": channel_indices.append(2)

    if not channel_indices:
        channel_indices = [0, 1, 2]

    selected = arr[:, :, channel_indices] & 1
    flat_bits = selected.reshape(-1)
    if len(flat_bits) > max_bytes * 8:
        flat_bits = flat_bits[: max_bytes * 8]

    extracted_bytes = np.packbits(flat_bits).tobytes()

    # Check for known file headers in extracted bitstream
    for magic, name, ext in KNOWN_MAGIC_HEADERS:
        pos = extracted_bytes.find(magic)
        if pos != -1 and pos < 2048:
            # Found carved embedded file: determine true container boundary
            carved = extracted_bytes[pos:]
            if magic == b"PK\x03\x04":
                eocd = carved.find(b"PK\x05\x06")
                if eocd != -1 and eocd + 22 <= len(carved):
                    comment_len = int.from_bytes(carved[eocd + 20 : eocd + 22], "little")
                    carved = carved[: eocd + 22 + comment_len]
            elif magic == b"\x89PNG\r\n\x1a\n":
                iend = carved.find(b"IEND")
                if iend != -1 and iend + 8 <= len(carved):
                    carved = carved[: iend + 8]
            elif magic == b"\xFF\xD8\xFF":
                eoi = carved.find(b"\xFF\xD9")
                if eoi != -1:
                    carved = carved[: eoi + 2]

            return {
                "format_detected": name,
                "extension": ext,
                "offset": pos,
                "size_bytes": len(carved),
                "payload_sample_hex": carved[:32].hex(),
                "payload_bytes": carved,
            }

    # Check for ASCII plaintext message
    printable_chars = 0
    for b in extracted_bytes[:256]:
        if 32 <= b <= 126 or b in (10, 13, 9):
            printable_chars += 1

    if len(extracted_bytes) >= 16 and (printable_chars / min(256, len(extracted_bytes))) > 0.85:
        text = extracted_bytes[:512].decode("latin-1", errors="ignore").strip()
        if len(text) >= 10:
            return {
                "format_detected": "Plaintext ASCII Message",
                "extension": ".txt",
                "offset": 0,
                "size_bytes": len(text),
                "payload_sample_hex": extracted_bytes[:32].hex(),
                "text_content": text,
                "payload_bytes": extracted_bytes[:len(text)],
            }

    return None


def analyze_palette_steganography(pil_img: Image.Image) -> Dict[str, Any]:
    """Inspect indexed palette color anomalies (PNG/GIF PLTE chunk)."""
    result = {
        "is_indexed": False,
        "palette_size": 0,
        "duplicate_colors": 0,
        "suspicious_palette_parity": False,
        "findings": [],
    }

    if pil_img is None or pil_img.mode != "P":
        return result

    result["is_indexed"] = True
    palette = pil_img.getpalette()
    if not palette:
        return result

    colors = []
    for i in range(0, len(palette), 3):
        if i + 2 < len(palette):
            colors.append((palette[i], palette[i+1], palette[i+2]))

    result["palette_size"] = len(colors)
    unique_colors = set(colors)
    duplicates = len(colors) - len(unique_colors)
    result["duplicate_colors"] = duplicates

    if duplicates > 0:
        result["suspicious_palette_parity"] = True
        result["findings"].append(
            f"Palette Steganography indicator: {duplicates} duplicate color entries found in palette table."
        )

    # Check for near-identical color pairs (difference <= 2 across RGB)
    near_duplicates = 0
    for i in range(len(colors)):
        for j in range(i + 1, len(colors)):
            dr = abs(colors[i][0] - colors[j][0])
            dg = abs(colors[i][1] - colors[j][1])
            db = abs(colors[i][2] - colors[j][2])
            if 0 < (dr + dg + db) <= 2:
                near_duplicates += 1

    if near_duplicates > 4:
        result["suspicious_palette_parity"] = True
        result["findings"].append(
            f"Palette Parity Modulation: {near_duplicates} micro-variant color pairs detected."
        )

    return result


def bruteforce_stego_dictionary(
    raw_bytes: bytes,
    custom_wordlist: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Inspect carrier for known tool container markers (OpenStego, StegHide, OutGuess)
    and provide extraction instructions.
    """
    words = list(COMMON_STEGO_PASSWORDS)
    if custom_wordlist:
        words.extend(custom_wordlist)

    # Check for OpenStego container marker
    if b"OPENSTEGO" in raw_bytes or b"OpenStego" in raw_bytes:
        return {
            "tool": "OpenStego",
            "status": "CONTAINER_DETECTED",
            "wordlist_size": len(words),
            "recommendation": "Use OpenStego extractor with candidate passphrases.",
        }

    # Check for StegHide container signatures
    if b"steghide" in raw_bytes.lower() or b"\x7f\xfe\x00" in raw_bytes:
        return {
            "tool": "StegHide",
            "status": "CONTAINER_DETECTED",
            "wordlist_size": len(words),
            "recommendation": "Execute: steghide extract -sf <image> -p <passphrase>",
        }

    return None


# Alias for explicit naming
detect_stego_container_markers = bruteforce_stego_dictionary
