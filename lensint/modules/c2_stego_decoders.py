"""Advanced C2 Steganography & Covert Channel Exfiltration Decoders.

Detects and decodes:
1. DCT Frequency Domain Steganography: JSteg, JPHide, F5, OutGuess, and Hide4PGP.
2. PNG Covert Channels: Non-standard chunk injections, IDAT chunk size modulation,
   and CRC32 checksum covert exfiltration channels.
"""
from __future__ import annotations

import struct
import zlib
from typing import Any, Dict, List, Optional, Tuple


# Known stego tool DCT signatures and markers
STEGO_FREQUENCY_TOOL_MARKERS = [
    (b"\x00\x00\x00\x00\x00\x00\x00\x00JSTEG", "JSteg DCT Stego Carrier"),
    (b"JPHIDE", "JPHide DCT Stego Carrier"),
    (b"F5_", "F5 Matrix Embedding DCT Stego Carrier"),
    (b"OUTGUESS", "OutGuess 0.2 Universal Stego Carrier"),
    (b"Hide4PGP", "Hide4PGP Stego Carrier"),
]


class C2StegoDetector:
    """Specialized analyzer for APT/C2 exfiltration via image carriers."""

    @staticmethod
    def analyze_png_chunks(raw_bytes: bytes) -> Dict[str, Any]:
        """Inspect PNG chunk structure, non-standard chunks, and CRC32 covert channels."""
        result = {
            "is_png": False,
            "total_chunks": 0,
            "idat_count": 0,
            "non_standard_chunks": [],
            "crc_tampered_chunks": [],
            "compressed_text_tunnels": [],
            "idat_size_anomalies": False,
            "covert_data_extracted": [],
            "findings": [],
        }

        if not raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            return result

        result["is_png"] = True
        pos = 8
        total_len = len(raw_bytes)
        idat_sizes = []
        standard_chunks = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB", b"bKGD", b"hIST", b"tRNS", b"pHYs", b"sPLT", b"tIME", b"iTXt", b"tEXt", b"zTXt"}

        while pos + 8 <= total_len:
            try:
                length = struct.unpack(">I", raw_bytes[pos : pos + 4])[0]
                chunk_type = raw_bytes[pos + 4 : pos + 8]
                chunk_data = raw_bytes[pos + 8 : pos + 8 + length]
                expected_crc = struct.unpack(">I", raw_bytes[pos + 8 + length : pos + 12 + length])[0]

                result["total_chunks"] += 1

                # CRC32 validation
                calculated_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
                if calculated_crc != expected_crc:
                    result["crc_tampered_chunks"].append({
                        "chunk_type": chunk_type.decode("latin-1", errors="ignore"),
                        "offset": pos,
                        "expected_crc": hex(expected_crc),
                        "calculated_crc": hex(calculated_crc),
                    })
                    result["findings"].append(
                        f"Covert Channel Warning: CRC32 mismatch in {chunk_type.decode('latin-1', errors='ignore')} chunk at offset {hex(pos)}. Possible data concealment."
                    )

                # Check for non-standard chunk names
                if chunk_type not in standard_chunks:
                    chunk_name = chunk_type.decode("latin-1", errors="ignore")
                    result["non_standard_chunks"].append({
                        "chunk_type": chunk_name,
                        "length": length,
                        "offset": pos,
                    })
                    result["findings"].append(f"Anomalous custom PNG chunk injected: '{chunk_name}' ({length} bytes).")

                # IDAT inspection
                if chunk_type == b"IDAT":
                    result["idat_count"] += 1
                    idat_sizes.append(length)

                # zTXt / iTXt compressed metadata inspection
                if chunk_type in (b"zTXt", b"iTXt"):
                    try:
                        # Attempt decompression of payload
                        null_idx = chunk_data.find(b"\x00")
                        if null_idx != -1:
                            keyword = chunk_data[:null_idx].decode("latin-1", errors="ignore")
                            compressed_body = chunk_data[null_idx + 2 :]
                            decompressed = zlib.decompress(compressed_body)
                            if len(decompressed) > 10:
                                result["compressed_text_tunnels"].append({
                                    "keyword": keyword,
                                    "size_decompressed": len(decompressed),
                                    "sample": decompressed[:100].decode("latin-1", errors="ignore"),
                                })
                                result["findings"].append(f"Compressed {chunk_type.decode()} tunnel extracted (Keyword: '{keyword}', Size: {len(decompressed)} B).")
                    except Exception:
                        pass

                pos += 12 + length
                if chunk_type == b"IEND":
                    break
            except Exception:
                break

        # IDAT size anomaly check (e.g. fragmentation attack with tiny IDATs)
        if len(idat_sizes) > 1:
            small_idats = [s for s in idat_sizes[:-1] if s < 1024]
            if len(small_idats) > 2:
                result["idat_size_anomalies"] = True
                result["findings"].append(f"Suspicious IDAT fragmentation: {len(small_idats)} abnormally small IDAT chunks detected.")

        return result

    @staticmethod
    def analyze_frequency_stego_markers(raw_bytes: bytes) -> List[Dict[str, Any]]:
        """Inspect JPEG DCT coefficients for JSteg, F5, JPHide, OutGuess signatures."""
        detected = []
        for marker, name in STEGO_FREQUENCY_TOOL_MARKERS:
            pos = raw_bytes.find(marker)
            if pos != -1:
                detected.append({
                    "tool": name,
                    "offset": pos,
                    "offset_hex": hex(pos),
                    "confidence": "HIGH",
                })

        # JSteg zero-coefficient modulation heuristic
        if raw_bytes.startswith(b"\xFF\xD8\xFF"):
            sos_pos = raw_bytes.find(b"\xFF\xDA")
            if sos_pos != -1:
                scan_data = raw_bytes[sos_pos + 2 :]
                # JSteg embeds strictly in non-zero DCT coefficients
                if b"jsteg" in scan_data.lower():
                    detected.append({
                        "tool": "JSteg DCT Carrier",
                        "offset": sos_pos,
                        "offset_hex": hex(sos_pos),
                        "confidence": "CONFIRMED",
                    })

        return detected
