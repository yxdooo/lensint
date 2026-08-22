import hashlib
import os
from typing import Optional
from PIL import Image

from lensint.core.models import IntegrityReport
from lensint.utils.image_ops import format_bytes
from lensint.utils.signatures import IMAGE_SIGNATURES


def analyze_integrity(file_path: str, raw_bytes: bytes, pil_img: Optional[Image.Image]) -> IntegrityReport:
    report = IntegrityReport()
    report.file_path = os.path.abspath(file_path)
    report.file_name = os.path.basename(file_path)
    report.file_size_bytes = len(raw_bytes)
    report.file_size_human = format_bytes(len(raw_bytes))

    report.md5 = hashlib.md5(raw_bytes).hexdigest()
    report.sha1 = hashlib.sha1(raw_bytes).hexdigest()
    report.sha256 = hashlib.sha256(raw_bytes).hexdigest()
    report.sha512 = hashlib.sha512(raw_bytes).hexdigest()

    _, ext = os.path.splitext(file_path)
    report.extension = ext.lower()

    detected_sig = None
    for sig in IMAGE_SIGNATURES:
        hdr = sig["header"]
        if raw_bytes.startswith(hdr):
            detected_sig = sig
            break
        if hdr == b"RIFF" and len(raw_bytes) >= 12 and raw_bytes[:4] == b"RIFF" and raw_bytes[8:12] == b"WEBP":
            detected_sig = sig
            break

    if detected_sig:
        report.detected_format = detected_sig["name"]
        report.detected_mime = detected_sig["mime"]
        valid_exts = detected_sig["extensions"]

        if report.extension not in valid_exts:
            report.extension_mismatch = True
            report.anomalies.append(
                f"File extension spoofing detected: file is named '{report.extension}' "
                f"but header signature matches '{detected_sig['name']}' ({detected_sig['mime']})."
            )
    else:
        if raw_bytes.startswith(b"MZ"):
            report.detected_format = "Windows Executable (PE/MZ)"
            report.detected_mime = "application/x-dosexec"
            report.extension_mismatch = True
            report.anomalies.append("Severe anomaly: file is a Windows Executable (MZ header) disguised with an image extension.")
        elif raw_bytes.startswith(b"\x7fELF"):
            report.detected_format = "Linux Executable (ELF)"
            report.detected_mime = "application/x-executable"
            report.extension_mismatch = True
            report.anomalies.append("Severe anomaly: file is a Linux ELF binary disguised with an image extension.")
        elif raw_bytes.startswith(b"PK\x03\x04"):
            report.detected_format = "ZIP Archive"
            report.detected_mime = "application/zip"
            report.extension_mismatch = True
            report.anomalies.append("Anomaly: file is a ZIP archive disguised with an image extension.")
        else:
            report.detected_format = "Unknown / Custom Binary"
            report.detected_mime = "application/octet-stream"
            if report.extension in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"]:
                report.extension_mismatch = True
                report.anomalies.append(f"Header signature does not match standard image formats for '{report.extension}'.")

    if pil_img is not None:
        report.dimensions = (pil_img.width, pil_img.height)
        report.color_mode = pil_img.mode
        report.has_alpha_channel = "A" in pil_img.mode
    else:
        report.is_corrupt_or_truncated = True
        report.anomalies.append("Failed to decode image structure: image data may be corrupted or truncated.")

    return report
