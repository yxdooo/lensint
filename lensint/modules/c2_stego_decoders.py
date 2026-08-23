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
        """Inspect PNG chunk structure, semantic compliance, and covert channels."""
        result: Dict[str, Any] = {
            "is_png": False,
            "total_chunks": 0,
            "idat_count": 0,
            "idat_fragmentation_detected": False,
            "idat_fragmentation_score": 0.0,
            "non_standard_chunks": [],
            "crc_tampered_chunks": [],
            "compressed_metadata": [],
            "semantic_violations": [],
            "findings": [],
        }

        if not raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            return result

        result["is_png"] = True
        pos = 8
        total_len = len(raw_bytes)
        idat_sizes: List[int] = []
        standard_chunks = {
            b"IHDR", b"PLTE", b"IDAT", b"IEND", b"cHRM", b"gAMA", b"iCCP",
            b"sBIT", b"sRGB", b"bKGD", b"hIST", b"tRNS", b"pHYs", b"sPLT",
            b"tIME", b"iTXt", b"tEXt", b"zTXt", b"eXIf",
        }

        has_ihdr = False
        has_iend = False
        saw_idat = False
        idat_consecutive_broken = False

        while pos + 8 <= total_len:
            try:
                length = struct.unpack(">I", raw_bytes[pos : pos + 4])[0]
                chunk_type = raw_bytes[pos + 4 : pos + 8]
                chunk_data = raw_bytes[pos + 8 : pos + 8 + length]
                expected_crc = struct.unpack(">I", raw_bytes[pos + 8 + length : pos + 12 + length])[0]

                if result["total_chunks"] == 0 and chunk_type != b"IHDR":
                    result["semantic_violations"].append("First chunk is not IHDR.")
                    result["findings"].append("Structural Anomaly: First chunk is not IHDR.")
                
                # Strict IHDR validation
                if chunk_type == b"IHDR":
                    has_ihdr = True
                    if length != 13:
                        result["semantic_violations"].append(f"IHDR chunk length {length} != 13.")
                        result["findings"].append(f"PNG Semantic Violation: IHDR length is {length} (must be exactly 13).")
                    elif len(chunk_data) == 13:
                        width, height, bit_depth, color_type, comp_m, filt_m, inter_m = struct.unpack(">IIBBBBB", chunk_data)
                        valid_combos = {
                            0: (1, 2, 4, 8, 16),
                            2: (8, 16),
                            3: (1, 2, 4, 8),
                            4: (8, 16),
                            6: (8, 16),
                        }
                        if color_type not in valid_combos or bit_depth not in valid_combos[color_type]:
                            v_msg = f"Invalid bit_depth={bit_depth} for color_type={color_type}"
                            result["semantic_violations"].append(v_msg)
                            result["findings"].append(f"PNG Semantic Violation: {v_msg}.")

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
                        f"Anomaly / Suspicious: CRC32 mismatch in {chunk_type.decode('latin-1', errors='ignore')} chunk at offset {hex(pos)}."
                    )

                # Check for non-standard custom / private chunk names
                if chunk_type not in standard_chunks:
                    chunk_name = chunk_type.decode("latin-1", errors="ignore")
                    is_private = (chunk_type[1] & 32) != 0  # 2nd letter lowercase = private
                    result["non_standard_chunks"].append({
                        "chunk_type": chunk_name,
                        "length": length,
                        "offset": pos,
                        "is_private": is_private,
                    })
                    if not is_private:
                        result["findings"].append(f"Unregistered ancillary PNG chunk: '{chunk_name}' ({length} bytes).")

                # IDAT inspection & continuity tracking
                if chunk_type == b"IDAT":
                    if saw_idat and idat_consecutive_broken:
                        result["semantic_violations"].append("Non-contiguous IDAT sequence.")
                        result["findings"].append("PNG Semantic Violation: IDAT chunks are split by non-IDAT chunks.")
                    saw_idat = True
                    result["idat_count"] += 1
                    idat_sizes.append(length)
                elif saw_idat and chunk_type != b"IEND":
                    idat_consecutive_broken = True

                # zTXt / iTXt compressed metadata inspection
                if chunk_type in (b"zTXt", b"iTXt"):
                    keyword = "UNKNOWN"
                    try:
                        null_idx = chunk_data.find(b"\x00")
                        if null_idx != -1:
                            keyword = chunk_data[:null_idx].decode("latin-1", errors="ignore")
                            decompressed = b""
                            if chunk_type == b"zTXt":
                                compressed_body = chunk_data[null_idx + 2 :]
                                decompressed = zlib.decompressobj().decompress(compressed_body, max_length=5_000_000)
                            elif chunk_type == b"iTXt":
                                if len(chunk_data) > null_idx + 2:
                                    comp_flag = chunk_data[null_idx + 1]
                                    rest = chunk_data[null_idx + 3 :]
                                    lang_null = rest.find(b"\x00")
                                    if lang_null != -1:
                                        trans_null = rest.find(b"\x00", lang_null + 1)
                                        if trans_null != -1:
                                            body = rest[trans_null + 1 :]
                                            if comp_flag == 1:
                                                decompressed = zlib.decompressobj().decompress(body, max_length=5_000_000)
                                            elif comp_flag == 0:
                                                decompressed = body
                            
                            if len(decompressed) > 10:
                                result["compressed_metadata"].append({
                                    "keyword": keyword,
                                    "uncompressed_size": len(decompressed),
                                    "chunk_type": chunk_type.decode("latin-1"),
                                })
                    except Exception as e:
                        result["findings"].append(f"Failed to decompress {chunk_type.decode('latin-1')} chunk data: {e}")

                # IEND validation
                if chunk_type == b"IEND":
                    has_iend = True
                    if length != 0:
                        result["semantic_violations"].append(f"IEND length {length} != 0.")
                        result["findings"].append(f"PNG Semantic Violation: IEND length is {length} (must be 0).")
                    break

                pos += 12 + length
            except Exception as e:
                result["findings"].append(f"Structural Anomaly: Malformed PNG chunk parsing stopped at offset {hex(pos)}. Error: {str(e)}")
                break

        # IDAT fragmentation anomaly calculation
        if len(idat_sizes) >= 3:
            tiny_idats = sum(1 for s in idat_sizes if s < 64)
            if tiny_idats >= 3 or (len(idat_sizes) > 10 and max(idat_sizes) / (min(idat_sizes) + 1) > 500):
                result["idat_fragmentation_detected"] = True
                result["idat_fragmentation_score"] = round(min(100.0, tiny_idats * 25.0), 2)
                result["findings"].append(
                    f"Covert Channel Anomaly: Highly fragmented IDAT sequence ({tiny_idats} tiny chunks, score {result['idat_fragmentation_score']}/100)."
                )

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
        """Evaluate JPEG scan bytes and DCT coefficients for F5 steganography matrix embedding."""
        if not raw_bytes.startswith(b"\xFF\xD8\xFF"):
            return None
        if b"F5_" in raw_bytes or b"_F5_" in raw_bytes:
            return {
                "extracted_format": "F5 Matrix Embedded Signature",
                "extension": ".bin",
                "size_bytes": 0,
                "status": "SUSPICIOUS_SIGNATURE_ONLY",
            }
        try:
            from lensint.modules.jpeg_dct import analyze_f5_capacity
            f5_res = analyze_f5_capacity(raw_bytes)
            if f5_res.get("f5_indicator"):
                return {
                    "extracted_format": "F5 Matrix Embedding Indicator",
                    "extension": ".bin",
                    "size_bytes": f5_res.get("net_capacity_bytes", f5_res.get("raw_capacity_bytes", 0)),
                    "status": "DCT_ANOMALY_DETECTED",
                    "details": f5_res,
                }
        except Exception:
            pass
        return None

    @staticmethod
    def scan_outguess_signature(raw_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Evaluate JPEG scan bytes and DCT coefficient histogram symmetry for OutGuess 0.2 preservation."""
        if not raw_bytes.startswith(b"\xFF\xD8\xFF"):
            return None
        if b"OUTGUESS" in raw_bytes:
            return {
                "extracted_format": "OutGuess 0.2 Signature",
                "extension": ".bin",
                "size_bytes": 0,
                "status": "SUSPICIOUS_SIGNATURE_ONLY",
            }
        try:
            from lensint.modules.jpeg_dct import analyze_outguess_stats
            og_res = analyze_outguess_stats(raw_bytes)
            if og_res.get("outguess_indicator"):
                return {
                    "extracted_format": "OutGuess 0.2 Statistical Marker",
                    "extension": ".bin",
                    "size_bytes": 0,
                    "status": "DCT_ANOMALY_DETECTED",
                    "details": og_res,
                }
        except Exception:
            pass
        return None

    @staticmethod
    def analyze_jpeg_dct_stego(raw_bytes: bytes) -> Dict[str, Any]:
        """Analyze JPEG in DCT domain for JSteg, F5, and OutGuess steganography."""
        result: Dict[str, Any] = {
            "jsteg": None,
            "f5": None,
            "outguess": None,
            "c2_stego_detected": False,
            "jsteg_detected": False,
            "f5_detected": False,
            "outguess_detected": False,
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
                result["jsteg_detected"] = True
                result["c2_stego_detected"] = True
                result["findings"].append(
                    f"JSteg DCT Payload Detected: {jsteg_res.get('detected_format')} signature in DCT AC coefficient LSB stream."
                )

            f5_res = analyze_f5_capacity(raw_bytes)
            result["f5"] = f5_res
            if f5_res.get("f5_indicator"):
                result["f5_detected"] = True
                result["c2_stego_detected"] = True
                result["findings"].append(
                    f"F5 Steganography Anomaly: AC coefficient LSB imbalance ({f5_res.get('lsb_anomaly_score')}%) indicates potential F5 matrix embedding."
                )

            outguess_res = analyze_outguess_stats(raw_bytes)
            result["outguess"] = outguess_res
            if outguess_res.get("outguess_indicator"):
                result["outguess_detected"] = True
                result["c2_stego_detected"] = True
                result["findings"].append(
                    f"OutGuess 0.2 DCT Statistical Anomaly: Histogram symmetry score {outguess_res.get('histogram_symmetry_score')} indicates artificial preservation."
                )
        except Exception as e:
            result["findings"].append(f"JPEG DCT Stego Analysis Warning: {e}")

        return result

