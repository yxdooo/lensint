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
        pos = raw_bytes.rfind(b'\x3B')
        if pos != -1 and pos + 1 < total:
            return True, pos + 1, total - (pos + 1), raw_bytes[pos + 1 :]
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
    try:
        arr = np.array(pil_img.convert('RGB'), dtype=np.uint8)
        packed = np.packbits((arr[:, :, 0] & 1).flatten()[:8192]).tobytes()
        if packed.startswith(b'PK\x03\x04'): return 'Embedded ZIP Archive in LSB'
        if packed.startswith(b'\x89PNG\r\n\x1a\n'): return 'Embedded PNG Image in LSB'
        if packed.startswith(b'\xFF\xD8\xFF'): return 'Embedded JPEG Image in LSB'
        if packed.startswith(b'\x7fELF') or packed.startswith(b'MZ'): return 'Embedded Executable Binary in LSB'
        if packed.startswith(b'%PDF-'): return 'Embedded PDF Document in LSB'
    except Exception:
        pass
    return None

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
