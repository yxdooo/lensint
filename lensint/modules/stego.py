import hashlib
import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from PIL import Image

from lensint.core.models import StegoReport
from lensint.utils.image_ops import format_bytes, numpy_to_base64_png
from lensint.utils.signatures import EMBEDDED_SIGNATURES


def _calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = {}
    for b in data: freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0: entropy -= p * math.log2(p)
    return round(entropy, 4)

def detect_overlay_data(raw_bytes: bytes) -> Tuple[bool, Optional[int], int, Optional[bytes]]:
    total = len(raw_bytes)
    if raw_bytes.startswith(b'\xFF\xD8\xFF'):
        pos = raw_bytes.rfind(b'\xFF\xD9')
        if pos != -1 and pos + 2 < total:
            return True, pos + 2, total - (pos + 2), raw_bytes[pos + 2 :]
    elif raw_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
        pos = raw_bytes.rfind(b'IEND')
        if pos != -1 and pos + 8 < total:
            return True, pos + 8, total - (pos + 8), raw_bytes[pos + 8 :]
    elif raw_bytes.startswith(b'GIF87a') or raw_bytes.startswith(b'GIF89a'):
        # GIF trailer is the 2-byte sequence 0x00 0x3B, NOT just 0x3B.
        # Searching for bare 0x3B produces false positives from frame data.
        pos = raw_bytes.rfind(b'\x00\x3B')
        if pos != -1 and pos + 2 < total:
            return True, pos + 2, total - (pos + 2), raw_bytes[pos + 2 :]
    return False, None, 0, None

def _is_valid_pe_header(raw_bytes: bytes, offset: int) -> bool:
    if offset + 0x40 > len(raw_bytes): return False
    try:
        pe_offset = int.from_bytes(raw_bytes[offset + 0x3C : offset + 0x40], byteorder='little')
        if 0 < pe_offset < 1024 * 1024:
            target = offset + pe_offset
            if target + 4 <= len(raw_bytes):
                return raw_bytes[target : target + 4] == b'PE\x00\x00'
    except Exception:
        pass
    return False

def scan_embedded_signatures(raw_bytes: bytes, overlay_offset: Optional[int] = None) -> List[Dict[str, Any]]:
    findings = []
    for sig in EMBEDDED_SIGNATURES:
        pat, name = sig['pattern'], sig['name']
        start = 0
        while True:
            pos = raw_bytes.find(pat, start)
            if pos == -1: break
            if name == 'Windows Executable (PE/MZ)' and not _is_valid_pe_header(raw_bytes, pos):
                start = pos + len(pat)
                continue
            is_ov = overlay_offset is not None and pos >= overlay_offset
            findings.append({'signature': name, 'category': sig['category'], 'offset': pos, 'offset_hex': hex(pos), 'in_overlay': is_ov, 'description': sig['description']})
            start = pos + len(pat)
            if len(findings) > 50: break
    return findings

def extract_lsb_hidden_payload(pil_img: Image.Image) -> Optional[str]:
    """Check all three RGB channels for LSB-embedded payloads.
    Real steganography tools (OpenStego, StegHide) distribute data across
    channels, so checking only red misses most real payloads.
    """
    try:
        arr = np.array(pil_img.convert('RGB'), dtype=np.uint8)
        KNOWN_SIGS = {
            b'PK\x03\x04': 'Embedded ZIP Archive in LSB',
            b'\x89PNG\r\n\x1a\n': 'Embedded PNG Image in LSB',
            b'\xFF\xD8\xFF': 'Embedded JPEG Image in LSB',
            b'\x7fELF': 'Embedded Executable Binary in LSB',
            b'MZ': 'Embedded Executable Binary in LSB',
            b'%PDF-': 'Embedded PDF Document in LSB',
        }
        # Check each channel individually and also the interleaved R+G+B combination
        channel_combinations = [
            (arr[:, :, 0], "Red channel"),
            (arr[:, :, 1], "Green channel"),
            (arr[:, :, 2], "Blue channel"),
            # Interleaved: common in StegHide / OpenStego
            (arr.reshape(-1, 3)[:, 0], "Interleaved-R"),
        ]
        for channel_arr, _ in channel_combinations:
            packed = np.packbits((channel_arr.flatten() & 1)[:8192]).tobytes()
            for sig, label in KNOWN_SIGS.items():
                if packed.startswith(sig):
                    return label
    except Exception:
        pass
    return None

KNOWN_STEGO_TOOL_SIGNATURES = [
    {"name": "OpenStego Carrier", "pattern": b"OPENSTEGO", "desc": "OpenStego default signature header"},
    {"name": "SilentEye Steganography", "pattern": b"SE\x00\x00", "desc": "SilentEye standard payload header"},
    {"name": "JPHide DCT Carrier", "pattern": b"\xFF\xFE\x00\x08JPHIDE", "desc": "JPHide embedded JPEG signature"},
    {"name": "StegHide Header Artifact", "pattern": b"\x73\x74\x65\x67\x68\x69\x64\x65", "desc": "StegHide unstripped identifier"},
    {"name": "F5 Steganography Matrix", "pattern": b"F5\x00\x01", "desc": "F5 algorithm coefficient header"},
]


def perform_rs_steganalysis(arr: np.ndarray) -> Tuple[bool, float]:
    """Perform RS (Regular / Singular) Steganalysis to detect LSB replacement.

    RS steganalysis divides the image into groups of 4 adjacent pixels and applies
    flipping masks M = [0, 1, 1, 0] and -M = [0, -1, -1, 0].
    For a natural clean image: R_M ≈ R_-M and S_M ≈ S_-M.
    When LSB embedding occurs, R_M decreases while S_M increases.

    Returns:
        (stego_detected: bool, estimated_embedding_rate: float in [0.0, 1.0])
    """
    try:
        # Work on green channel (most sensitive for RGB images) or grayscale
        if len(arr.shape) == 3:
            channel = arr[:, :, 1].astype(np.int32)
        else:
            channel = arr.astype(np.int32)

        h, w = channel.shape
        flat = channel.flatten()
        # Ensure length is multiple of 4
        n_pixels = (len(flat) // 4) * 4
        if n_pixels < 1024:
            return False, 0.0

        groups = flat[:n_pixels].reshape(-1, 4)

        # Discrimination function: sum of absolute differences of adjacent pixels
        def variation(g):
            return np.abs(g[:, 1] - g[:, 0]) + np.abs(g[:, 2] - g[:, 1]) + np.abs(g[:, 3] - g[:, 2])

        # Flipping function: F_1(x) = x XOR 1 (flip LSB)
        def flip_pos(g):
            res = g.copy()
            res[:, 1] = res[:, 1] ^ 1
            res[:, 2] = res[:, 2] ^ 1
            return res

        # F_{-1}(x) = (x-1) if x is even else (x+1)
        def flip_neg(g):
            res = g.copy()
            for col in (1, 2):
                c = res[:, col]
                res[:, col] = np.where(c % 2 == 0, c - 1, c + 1)
            return res

        v_orig = variation(groups)
        v_pos = variation(flip_pos(groups))
        v_neg = variation(flip_neg(groups))

        # Count Regular (v_flipped > v_orig) and Singular (v_flipped < v_orig)
        r_m = np.mean(v_pos > v_orig)
        s_m = np.mean(v_pos < v_orig)
        r_neg = np.mean(v_neg > v_orig)
        s_neg = np.mean(v_neg < v_orig)

        # Discrepancy indicates LSB modification
        d0 = r_m - s_m
        d1 = r_neg - s_neg

        # Estimation of embedding rate p:
        # In clean images, d0 ≈ d1. In fully embedded images, d0 ≈ 0.
        diff = abs(d0 - d1)
        if diff > 0.05:
            # Significant RS imbalance: estimate embedding rate
            est_rate = float(min(1.0, max(0.0, float(diff) * 3.5)))
            return True, round(est_rate, 3)
        return False, 0.0
    except Exception:
        return False, 0.0


def scan_stego_tool_signatures(raw_bytes: bytes) -> List[str]:
    """Scan raw image bytes for specific steganography tool signatures."""
    detected = []
    for sig in KNOWN_STEGO_TOOL_SIGNATURES:
        if sig["pattern"] in raw_bytes:
            detected.append(f"{sig['name']}: {sig['desc']}")
    return detected


def analyze_stego(raw_bytes: bytes, pil_img: Optional[Image.Image], generate_visuals: bool = True) -> StegoReport:
    report = StegoReport()
    has_overlay, offset, size, overlay_bytes = detect_overlay_data(raw_bytes)
    if has_overlay and overlay_bytes:
        report.has_overlay_data = True
        report.overlay_offset = offset
        report.overlay_size_bytes = size
        report.overlay_sha256 = hashlib.sha256(overlay_bytes).hexdigest()
        report.overlay_preview_hex = overlay_bytes[:32].hex(' ')
        report.findings.append(f'Hidden overlay data detected! {format_bytes(size)} ({size} bytes) appended past EOF at {hex(offset)}.')

    signatures = scan_embedded_signatures(raw_bytes, offset)
    report.embedded_signatures = signatures
    for s in signatures:
        cat_name = s['category']
        sig_name = s['signature']
        off_hex = s['offset_hex']
        loc = 'in appended overlay' if s['in_overlay'] else 'inside image body'
        report.findings.append(f'Found embedded {cat_name} signature: {sig_name} at {off_hex} ({loc}).')

    # Stego tool signature scanning (StegHide, OpenStego, etc.)
    tool_sigs = scan_stego_tool_signatures(raw_bytes)
    report.stego_tool_signatures = tool_sigs
    for ts in tool_sigs:
        report.findings.append(f"Stego tool signature identified: {ts}")

    if pil_img is not None:
        try:
            arr = np.array(pil_img.convert('RGB'), dtype=np.uint8)
            entropies, total = {}, 0.0
            for idx, name in enumerate(['Red', 'Green', 'Blue']):
                packed = np.packbits((arr[:, :, idx] & 1).flatten()).tobytes()
                ent = _calculate_entropy(packed)
                entropies[name] = ent
                total += ent
            avg_ent = round(total / 3.0, 4)
            entropies['Average'] = avg_ent
            report.lsb_entropy = entropies
            report.lsb_stego_detected = avg_ent >= 7.95
            report.lsb_stego_confidence = min(100.0, max(0.0, (avg_ent - 7.5) * 200.0)) if avg_ent >= 7.5 else 0.0

            # RS Steganalysis
            rs_detected, rs_rate = perform_rs_steganalysis(arr)
            report.rs_steganalysis_detected = rs_detected
            report.rs_estimated_embedding_rate = rs_rate
            if rs_detected:
                report.findings.append(
                    f"RS Steganalysis alert: Non-natural LSB distribution detected (Estimated embedding capacity used: {int(rs_rate*100)}%)."
                )

            payload_type = extract_lsb_hidden_payload(pil_img)
            report.extracted_payload_type = payload_type
            if payload_type:
                report.findings.append(f'Extracted carrier payload signature: {payload_type}.')

            if generate_visuals:
                report.bitplane_b64_images['plane_0_lsb'] = numpy_to_base64_png((arr & 1) * 255)
                report.bitplane_b64_images['plane_7_msb'] = numpy_to_base64_png(((arr >> 7) & 1) * 255)

            if report.lsb_stego_detected:
                report.findings.append(f'Suspicious LSB entropy detected (Average: {avg_ent}/8.0). High randomness indicates stego payload.')
        except Exception as e:
            report.findings.append(f'LSB error: {str(e)}')
    return report
