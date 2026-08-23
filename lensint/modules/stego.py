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
    """Detect trailing overlay data appended after the valid image container boundary.
    
    Uses forward container parsing (PNG chunk stream, JPEG EOI marker, GIF block stream)
    to prevent false offsets caused by embedded images inside the overlay payload.
    """
    total = len(raw_bytes)
    if total < 16:
        return False, None, 0, None

    # 1. PNG Forward Chunk Walk
    if raw_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
        offset = 8
        while offset + 8 <= total:
            chunk_len = int.from_bytes(raw_bytes[offset : offset + 4], "big")
            chunk_type = raw_bytes[offset + 4 : offset + 8]
            next_offset = offset + 12 + chunk_len
            if chunk_type == b'IEND':
                end_pos = offset + 12
                if end_pos < total:
                    return True, end_pos, total - end_pos, raw_bytes[end_pos:]
                return False, None, 0, None
            if next_offset > total:
                break
            offset = next_offset

    # 2. JPEG Marker Stream Walk
    elif raw_bytes.startswith(b'\xFF\xD8\xFF'):
        pos = 2
        in_sos = False
        while pos + 1 < total:
            if not in_sos:
                if raw_bytes[pos] != 0xFF:
                    break
                marker = raw_bytes[pos + 1]
                if marker == 0xD9:  # EOI
                    end_pos = pos + 2
                    if end_pos < total:
                        return True, end_pos, total - end_pos, raw_bytes[end_pos:]
                    return False, None, 0, None
                elif marker in (0xD8, 0x01) or (0xD0 <= marker <= 0xD7):
                    pos += 2
                elif marker == 0xDA:  # SOS
                    if pos + 4 <= total:
                        sos_len = int.from_bytes(raw_bytes[pos + 2 : pos + 4], "big")
                        pos += 2 + sos_len
                        in_sos = True
                    else:
                        break
                else:
                    if pos + 4 <= total:
                        seg_len = int.from_bytes(raw_bytes[pos + 2 : pos + 4], "big")
                        pos += 2 + seg_len
                    else:
                        break
            else:
                # Inside entropy-coded scan, find next marker
                ff_pos = raw_bytes.find(b'\xFF', pos)
                if ff_pos == -1 or ff_pos + 1 >= total:
                    break
                nxt = raw_bytes[ff_pos + 1]
                if nxt == 0x00 or (0xD0 <= nxt <= 0xD7):
                    pos = ff_pos + 2
                elif nxt == 0xD9:  # EOI
                    end_pos = ff_pos + 2
                    if end_pos < total:
                        return True, end_pos, total - end_pos, raw_bytes[end_pos:]
                    return False, None, 0, None
                else:
                    in_sos = False
                    pos = ff_pos

    # 3. GIF Block Stream Walk
    elif raw_bytes.startswith(b'GIF87a') or raw_bytes.startswith(b'GIF89a'):
        from lensint.modules.memory_forensics import _carve_gif_structural
        gif_bytes = _carve_gif_structural(raw_bytes, 0)
        if gif_bytes and len(gif_bytes) < total:
            end_pos = len(gif_bytes)
            return True, end_pos, total - end_pos, raw_bytes[end_pos:]

    # Fallback for other formats (BMP, WEBP)
    if raw_bytes.startswith(b'BM') and total > 6:
        bmp_size = int.from_bytes(raw_bytes[2:6], "little")
        if 54 <= bmp_size < total:
            return True, bmp_size, total - bmp_size, raw_bytes[bmp_size:]

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
        # Check each channel individually and also the interleaved RGB combination
        channel_combinations = [
            (arr[:, :, 0].flatten(), "Red channel"),
            (arr[:, :, 1].flatten(), "Green channel"),
            (arr[:, :, 2].flatten(), "Blue channel"),
            # Interleaved: common in StegHide / OpenStego
            (arr.flatten(), "Interleaved-RGB"),
        ]

        def _is_valid_zip(data: bytes, pos: int) -> bool:
            # Minimal structural validation for ZIP Local File Header fields
            if pos + 30 > len(data):
                return False
            comp_method = int.from_bytes(data[pos + 8 : pos + 10], "little")
            if comp_method not in (0, 8, 12, 14, 99):  # Common valid zip compression methods
                return False
            return b"PK\x01\x02" in data[pos:] or b"PK\x05\x06" in data[pos:] or comp_method in (0, 8)

        # Scan deeper (up to 64KB instead of 2KB) to catch payloads with offsets
        for channel_arr, _ in channel_combinations:
            packed = np.packbits((channel_arr & 1)[: 524288]).tobytes()  # 65536 bytes
            for sig, label in KNOWN_SIGS.items():
                pos = packed.find(sig)
                if pos != -1 and pos < 1024:  # Payload must start somewhat early
                    # Add container validation to reduce false positives
                    if sig == b'MZ':
                        if not _is_valid_pe_header(packed, pos):
                            continue
                    if sig == b'PK\x03\x04':
                        if not _is_valid_zip(packed, pos):
                            continue
                    return f"{label} (Offset: {pos} bytes)"
    except Exception:
        pass
    return None

KNOWN_STEGO_TOOL_SIGNATURES = [
    {"name": "OpenStego Carrier", "pattern": b"OPENSTEGO", "desc": "OpenStego default signature header"},
    {"name": "SilentEye Steganography", "pattern": b"SE\x00\x00", "desc": "SilentEye standard payload header"},
    {"name": "JPHide DCT Carrier", "pattern": b"\xFF\xFE\x00\x08JPHIDE", "desc": "JPHide embedded JPEG signature"},
    {"name": "Camouflage Cloaked", "pattern": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x55\xAA\x55\xAA", "desc": "Camouflage file hider marker"},
]


def perform_rs_steganalysis(arr: np.ndarray) -> Tuple[bool, float]:
    """Perform Fridrich et al. RS (Regular-Singular) Steganalysis on image array.
    
    Divides pixels into contiguous disjoint groups and measures variation
    under dual flipping functions F_1 and F_{-1}.
    
    Returns:
        (stego_detected: bool, estimated_embedding_rate: float)
    """
    try:
        # Evaluate green channel or luminance
        if len(arr.shape) == 3:
            flat = arr[:, :, 1].flatten()
        else:
            flat = arr.flatten()

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

        # F_{-1}(x) = (x-1) if x is even else (x+1), clipped to [0, 255]
        def flip_neg(g):
            res = g.copy()
            for col in (1, 2):
                c = res[:, col].astype(np.int16)
                flipped = np.where(c % 2 == 0, c - 1, c + 1)
                res[:, col] = np.clip(flipped, 0, 255).astype(np.uint8)
            return res

        # F_0(x) with all LSBs flipped (complement carrier)
        def flip_all_lsb(g):
            res = g.copy()
            return res ^ 1

        v_orig = variation(groups)
        v_pos = variation(flip_pos(groups))
        v_neg = variation(flip_neg(groups))

        # Count Regular (v_flipped > v_orig) and Singular (v_flipped < v_orig)
        r_m = float(np.mean(v_pos > v_orig))
        s_m = float(np.mean(v_pos < v_orig))
        r_neg = float(np.mean(v_neg > v_orig))
        s_neg = float(np.mean(v_neg < v_orig))

        # Complement image LSB group variations
        groups_comp = flip_all_lsb(groups)
        v_comp_orig = variation(groups_comp)
        v_comp_pos = variation(flip_pos(groups_comp))
        v_comp_neg = variation(flip_neg(groups_comp))

        r_m_c = float(np.mean(v_comp_pos > v_comp_orig))
        s_m_c = float(np.mean(v_comp_pos < v_comp_orig))
        r_neg_c = float(np.mean(v_comp_neg > v_comp_orig))
        s_neg_c = float(np.mean(v_comp_neg < v_comp_orig))

        d0 = r_m - s_m
        d_neg0 = r_neg - s_neg
        d1 = r_m_c - s_m_c
        d_neg1 = r_neg_c - s_neg_c

        # Fridrich standard polynomial root estimation
        a = 2.0 * (d1 + d0)
        b = (d_neg0 - d_neg1) - d1 - 3.0 * d0
        c_val = d0 - d_neg0

        est_p = 0.0
        diff = abs(d0 - d_neg0)

        if abs(a) > 1e-6:
            discriminant = b**2 - 4.0 * a * c_val
            if discriminant >= 0:
                root1 = (-b + math.sqrt(discriminant)) / (2.0 * a)
                root2 = (-b - math.sqrt(discriminant)) / (2.0 * a)
                # Select root with smallest absolute magnitude
                z = root1 if abs(root1) <= abs(root2) else root2
                if abs(z - 0.5) > 1e-6:
                    est_p = abs(z / (z - 0.5))
        else:
            if abs(d1 - d_neg1 + d_neg0 - d0) > 1e-6:
                est_p = abs((d0 - d_neg0) / (d1 - d_neg1 + d_neg0 - d0))

        est_p = float(min(1.0, max(0.0, est_p)))

        # Threshold 0.08 (Fridrich et al. standard) prevents false positives
        if diff > 0.08 and est_p > 0.05:
            return True, round(est_p, 3)
        return False, 0.0
    except Exception:
        return False, 0.0


def perform_chi_square_steganalysis(arr: np.ndarray) -> Tuple[bool, float]:
    """Perform Westfeld's Chi-Square (χ²) Steganalysis on Pairs of Values (PoVs).
    
    In natural images, adjacent even/odd histogram pairs (2k, 2k+1) have differing counts.
    Sequential LSB embedding equalizes these frequencies towards their mean.
    
    Returns:
        (stego_detected: bool, chi_square_p_value: float)
    """
    try:
        # Evaluate across channels if available, default to flattening
        if len(arr.shape) == 3:
            channel = arr[:, :, 1].flatten()
        else:
            channel = arr.flatten()

        if len(channel) < 2048:
            return False, 0.0

        counts = np.bincount(channel, minlength=256)
        chi_square = 0.0
        degrees_of_freedom = 0

        for k in range(0, 256, 2):
            h_even = float(counts[k])
            h_odd = float(counts[k + 1])
            pair_sum = h_even + h_odd
            if pair_sum > 10:
                # Full chi-square contribution: ((h_even - E)^2 + (h_odd - E)^2) / E = (h_even - h_odd)^2 / (h_even + h_odd)
                chi_square += ((h_even - h_odd) ** 2) / pair_sum
                degrees_of_freedom += 1

        if degrees_of_freedom < 10:
            return False, 0.0

        dof = max(1, degrees_of_freedom - 1)
        try:
            from scipy.stats import chi2
            p_val = chi2.sf(chi_square, dof)  # exact survival function
        except ImportError:
            # Fallback normal approximation for Chi-Square distribution p-value
            z = (chi_square - dof) / np.sqrt(2.0 * dof)
            p_val = float(0.5 * (1.0 - math.erf(z / math.sqrt(2.0))))
            
        p_equalized = float(p_val)
        chi_ratio = chi_square / float(dof)
        is_stego = (p_equalized >= 0.10) or (chi_ratio <= 1.25)
        return is_stego, round(p_equalized, 4)
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

    # Stego Passphrase dictionary check
    try:
        from lensint.modules.stego_extract import bruteforce_stego_dictionary, analyze_palette_steganography
        dict_hit = bruteforce_stego_dictionary(raw_bytes)
        if dict_hit:
            report.findings.append(f"Stego Carrier Tool: {dict_hit['tool']} ({dict_hit['status']}).")

        # Palette steganography check
        if pil_img is not None:
            pal_res = analyze_palette_steganography(pil_img)
            for f in pal_res.get("findings", []):
                report.findings.append(f)
    except Exception:
        pass

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

            # Chi-Square (χ²) Steganalysis
            chi_detected, chi_p = perform_chi_square_steganalysis(arr)
            if chi_detected:
                report.findings.append(
                    f"Chi-Square (χ²) Steganalysis alert: PoV frequency equalization detected (Confidence: {int(chi_p * 100)}%)."
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
