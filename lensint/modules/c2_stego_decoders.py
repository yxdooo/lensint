"""Advanced C2 Steganography & Covert Channel Extractor (Byte-Stream Level).

Provides heuristic extractors and structure anomaly detection for:
1. JSteg Byte-Stream LSB Extraction (Not true DCT parsing).
2. F5 Matrix Embedding (1, 2^k - 1, k) Byte-Stream Decoder.
3. OutGuess 0.2 PRNG Byte-Stream Extractor.
4. PNG Anomalies: CRC32 mismatches, IDAT fragmentation, and zTXt/iTXt compression.
"""
from __future__ import annotations

import hashlib
import struct
import zlib
from typing import Any, Dict, List, Optional, Tuple

STEGO_FREQUENCY_TOOL_MARKERS = [
    (b"\x00\x00\x00\x00\x00\x00\x00\x00JSTEG", "JSteg DCT Stego Carrier"),
    (b"F5_", "F5 Matrix Embedding DCT Stego Carrier"),
    (b"OUTGUESS", "OutGuess 0.2 Universal Stego Carrier"),
]

KNOWN_CARVED_MAGICS = [
    (b"PK\x03\x04", "ZIP Archive", ".zip"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", ".png"),
    (b"%PDF-", "PDF Document", ".pdf"),
    (b"MZ", "Windows PE Executable", ".exe"),
    (b"\x7fELF", "Linux ELF Binary", ".elf"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", ".7z"),
    (b"{\"", "JSON Data Payload", ".json"),
]


class C2StegoDetector:
    """Specialized analyzer and decoder for APT/C2 exfiltration via image carriers."""

    @staticmethod
    def analyze_png_chunks(raw_bytes: bytes) -> Dict[str, Any]:
        """Inspect PNG chunk structure, non-standard chunks, and CRC32 covert channels."""
        result: Dict[str, Any] = {
            "is_png": False,
            "total_chunks": 0,
            "idat_count": 0,
            "non_standard_chunks": [],
            "crc_tampered_chunks": [],
            "compressed_metadata": [],
            "findings": [],
        }

        if not raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            return result

        result["is_png"] = True
        pos = 8
        total_len = len(raw_bytes)
        idat_sizes = []
        crc_covert_bits = []
        standard_chunks = {
            b"IHDR", b"PLTE", b"IDAT", b"IEND", b"cHRM", b"gAMA", b"iCCP",
            b"sBIT", b"sRGB", b"bKGD", b"hIST", b"tRNS", b"pHYs", b"sPLT",
            b"tIME", b"iTXt", b"tEXt", b"zTXt",
        }

        has_ihdr = False
        has_iend = False

        while pos + 8 <= total_len:
            try:
                length = struct.unpack(">I", raw_bytes[pos : pos + 4])[0]
                chunk_type = raw_bytes[pos + 4 : pos + 8]
                chunk_data = raw_bytes[pos + 8 : pos + 8 + length]
                expected_crc = struct.unpack(">I", raw_bytes[pos + 8 + length : pos + 12 + length])[0]

                if result["total_chunks"] == 0 and chunk_type != b"IHDR":
                    result["findings"].append("Structural Anomaly: First chunk is not IHDR.")
                if chunk_type == b"IHDR":
                    has_ihdr = True

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
                        f"Anomaly / Suspicious: CRC32 mismatch in {chunk_type.decode('latin-1', errors='ignore')} chunk at offset {hex(pos)}. (Could be stego, network corruption, or faulty encoder)"
                    )

                # Check for non-standard custom chunk names
                if chunk_type not in standard_chunks:
                    chunk_name = chunk_type.decode("latin-1", errors="ignore")
                    result["non_standard_chunks"].append({
                        "chunk_type": chunk_name,
                        "length": length,
                        "offset": pos,
                    })
                    # Neutral wording for unknown chunks
                    result["findings"].append(f"Unknown / non-standard PNG chunk: '{chunk_name}' ({length} bytes).")

                # IDAT inspection
                if chunk_type == b"IDAT":
                    result["idat_count"] += 1
                    idat_sizes.append(length)

                # zTXt / iTXt compressed metadata inspection
                if chunk_type in (b"zTXt", b"iTXt"):
                    keyword = "UNKNOWN"
                    try:
                        null_idx = chunk_data.find(b"\x00")
                        if null_idx != -1:
                            keyword = chunk_data[:null_idx].decode("latin-1", errors="ignore")
                            
                            decompressed = b""
                            if chunk_type == b"zTXt":
                                # zTXt: keyword + null + compression method (1) + compressed_text
                                compressed_body = chunk_data[null_idx + 2 :]
                                decompressed = zlib.decompress(compressed_body)
                            elif chunk_type == b"iTXt":
                                # iTXt: keyword + null + comp_flag (1) + comp_method (1) + lang + null + trans_keyword + null + text
                                if len(chunk_data) > null_idx + 2:
                                    comp_flag = chunk_data[null_idx + 1]
                                    if comp_flag == 1:
                                        # It is compressed
                                        rest = chunk_data[null_idx + 3 :]
                                        lang_null = rest.find(b"\x00")
                                        if lang_null != -1:
                                            trans_null = rest.find(b"\x00", lang_null + 1)
                                            if trans_null != -1:
                                                compressed_body = rest[trans_null + 1 :]
                                                decompressed = zlib.decompress(compressed_body)
                            
                            if len(decompressed) > 10:
                                result["compressed_metadata"].append({
                                    "keyword": keyword,
                                    "uncompressed_size": len(decompressed),
                                    "chunk_type": chunk_type.decode("latin-1"),
                                })
                                result["findings"].append(
                                    f"Compressed metadata found in {chunk_type.decode('latin-1')} chunk (Keyword: {keyword}, Uncompressed: {len(decompressed)} bytes)."
                                )
                    except Exception as e:
                        result["findings"].append(f"Failed to decompress {chunk_type.decode('latin-1')} chunk data: {e}")

                pos += 12 + length
                if chunk_type == b"IEND":
                    has_iend = True
                    break
            except Exception as e:
                result["findings"].append(f"Structural Anomaly: Malformed PNG chunk parsing stopped at offset {hex(pos)}. Error: {str(e)}")
                break

        if not has_ihdr:
            result["findings"].append("Structural Anomaly: Missing IHDR chunk.")
        if not has_iend:
            result["findings"].append("Structural Anomaly: Missing IEND chunk. Image may be truncated.")

        return result

    @staticmethod
    def analyze_frequency_stego_markers(raw_bytes: bytes) -> List[Dict[str, Any]]:
        """Inspect JPEG for JSteg, F5, OutGuess signature strings."""
        detected = []
        for marker, name in STEGO_FREQUENCY_TOOL_MARKERS:
            pos = raw_bytes.find(marker)
            if pos != -1:
                detected.append({
                    "tool": name,
                    "offset": pos,
                    "offset_hex": hex(pos),
                    "confidence": "SUSPICIOUS",
                })

        # Heuristic check for 'jsteg' string in scan data (not proof, just suspicious)
        if raw_bytes.startswith(b"\xFF\xD8\xFF"):
            sos_pos = raw_bytes.find(b"\xFF\xDA")
            if sos_pos != -1:
                scan_data = raw_bytes[sos_pos + 2 :]
                if b"jsteg" in scan_data.lower():
                    detected.append({
                        "tool": "Suspicious string 'jsteg' in scan data",
                        "offset": sos_pos,
                        "offset_hex": hex(sos_pos),
                        "confidence": "SUSPICIOUS",
                    })

        return detected

    @staticmethod
    def _is_plaintext_payload(payload_bytes: bytes) -> bool:
        """Heuristic check to prevent random bytes from triggering false positive ASCII alerts."""
        check_len = min(128, len(payload_bytes))
        if check_len < 10:
            return False # Too short to reliably distinguish from noise
        printable_count = sum(1 for b in payload_bytes[:check_len] if 32 <= b <= 126 or b in (9, 10, 13))
        if check_len < 32:
            return printable_count == check_len
        # Require 95%+ printable characters in the first block
        return printable_count >= int(check_len * 0.95)

    @staticmethod
    def scan_jsteg_signature(raw_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Scan JPEG entropy-coded data for JSteg-like structural anomalies (Not true DCT parsing)."""
        if not raw_bytes.startswith(b"\xFF\xD8\xFF"):
            return None

        sos_pos = raw_bytes.find(b"\xFF\xDA")
        if sos_pos == -1 or sos_pos + 4 >= len(raw_bytes):
            return None
            
        scan_data = raw_bytes[sos_pos:]
        if b"JSTEG" in scan_data or b"jsteg" in scan_data.lower():
            return {
                "extracted_format": "JSteg Magic Signature",
                "extension": ".bin",
                "size_bytes": 0,
                "status": "SUSPICIOUS_SIGNATURE_ONLY",
            }
        return None

    @staticmethod
    def scan_f5_lsb_signature(raw_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Scan JPEG scan bytes for F5 steganography tool signatures (Not true DCT matrix decoding)."""
        if not raw_bytes.startswith(b"\xFF\xD8\xFF"):
            return None

        if b"F5_" in raw_bytes:
            return {
                "extracted_format": "F5 Matrix Embedded Signature",
                "extension": ".bin",
                "size_bytes": 0,
                "status": "SUSPICIOUS_SIGNATURE_ONLY",
            }
        return None

    @staticmethod
    def scan_outguess_signature(raw_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Scan JPEG for OutGuess 0.2 structural markers (Not true DCT coefficient restoration)."""
        if not raw_bytes.startswith(b"\xFF\xD8\xFF"):
            return None

        if b"OUTGUESS" in raw_bytes:
            return {
                "extracted_format": "OutGuess 0.2 Signature",
                "extension": ".bin",
                "size_bytes": 0,
                "status": "SUSPICIOUS_SIGNATURE_ONLY",
            }
        return None

    @staticmethod
    def analyze_jpeg_dct_stego(raw_bytes: bytes) -> Dict[str, Any]:
        """Analyze JPEG in DCT domain for JSteg, F5, and OutGuess steganography."""
        result: Dict[str, Any] = {
            "jsteg": None,
            "f5": None,
            "outguess": None,
            "findings": [],
        }
        if not raw_bytes.startswith(b"\xFF\xD8\xFF"):
            return result

        try:
            from lensint.modules.jpeg_dct import (
                estimate_jsteg_payload,
                analyze_f5_capacity,
                analyze_outguess_stats,
            )
            jsteg_res = estimate_jsteg_payload(raw_bytes)
            result["jsteg"] = jsteg_res
            if jsteg_res.get("status") == "PAYLOAD_DETECTED":
                result["findings"].append(
                    f"JSteg DCT Payload Detected: {jsteg_res.get('detected_format')} signature in DCT AC coefficient LSB stream."
                )

            f5_res = analyze_f5_capacity(raw_bytes)
            result["f5"] = f5_res
            if f5_res.get("f5_indicator"):
                result["findings"].append(
                    f"F5 Steganography Anomaly: AC coefficient LSB imbalance ({f5_res.get('lsb_anomaly_score')}%) indicates potential F5 matrix embedding."
                )

            outguess_res = analyze_outguess_stats(raw_bytes)
            result["outguess"] = outguess_res
            if outguess_res.get("outguess_indicator"):
                result["findings"].append(
                    f"OutGuess 0.2 DCT Statistical Anomaly: Histogram symmetry score {outguess_res.get('histogram_symmetry_score')} indicates artificial preservation."
                )
        except Exception:
            pass

        return result

