import hashlib
import os
from typing import Optional, Tuple
import numpy as np
from PIL import Image

from lensint.core.models import IntegrityReport
from lensint.utils.image_ops import format_bytes
from lensint.utils.signatures import IMAGE_SIGNATURES

COMMON_SCREEN_RESOLUTIONS = {
    # Desktop displays
    (1920, 1080), (1080, 1920),
    (2560, 1440), (1440, 2560),
    (3840, 2160), (2160, 3840),
    (1366, 768), (768, 1366),
    (1440, 900), (900, 1440),
    (1680, 1050), (1050, 1680),
    (1280, 720), (720, 1280),
    (1280, 800), (800, 1280),
    (1600, 900), (900, 1600),
    (2880, 1800), (1800, 2880),
    (3024, 1964), (1964, 3024),
    (3456, 2234), (2234, 3456),
    # Mobile & Tablet displays
    (1170, 2532), (2532, 1170),
    (1284, 2778), (2778, 1284),
    (1290, 2796), (2796, 1290),
    (1179, 2556), (2556, 1179),
    (1242, 2688), (2688, 1242),
    (828, 1792), (1792, 828),
    (1125, 2436), (2436, 1125),
    (750, 1334), (1334, 750),
    (1080, 2340), (2340, 1080),
    (1080, 2400), (2400, 1080),
    (1440, 3040), (3040, 1440),
    (1440, 3120), (3120, 1440),
    (1440, 3200), (3200, 1440),
    (720, 1600), (1600, 720),
    (2048, 2732), (2732, 2048),
    (1668, 2388), (2388, 1668),
    (1640, 2360), (2360, 1640),
}


def detect_screenshot_characteristics(pil_img: Image.Image, filename: str, is_png: bool) -> Tuple[bool, Optional[str]]:
    w, h = pil_img.size
    name_lower = filename.lower()
    has_screenshot_name = any(k in name_lower for k in ["screenshot", "screen_shot", "screen shot", "ekran", "capture", "snip", "prtscr"])

    # 1. Exact resolution match
    if (w, h) in COMMON_SCREEN_RESOLUTIONS:
        if is_png or has_screenshot_name:
            stype = "Mobile Screen Capture" if max(w, h) / (min(w, h) + 1e-6) >= 1.8 else "Desktop Screen Capture"
            return True, stype

    # 2. Check for typical UI raster flat color runs & sharp UI lines
    try:
        arr = np.array(pil_img.convert("RGB"), dtype=np.int32)
        # Check horizontal and vertical neighbor difference zero rates
        diff_x = arr[:, 1:, :] - arr[:, :-1, :]
        diff_y = arr[1:, :, :] - arr[:-1, :, :]
        zero_x = np.mean(np.all(diff_x == 0, axis=2))
        zero_y = np.mean(np.all(diff_y == 0, axis=2))

        # UI screen captures typically have >= 25% identical neighboring pixels due to window bars, backgrounds, and text layout
        if zero_x >= 0.22 or zero_y >= 0.22 or (zero_x >= 0.15 and is_png and has_screenshot_name):
            stype = "Digital UI Screen Capture / Framebuffer"
            return True, stype
    except Exception:
        pass

    if has_screenshot_name:
        return True, "Screen Capture (Identified by filename)"

    return False, None


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

        is_png = report.detected_format == "PNG" or report.extension == ".png"
        is_sc, sc_type = detect_screenshot_characteristics(pil_img, report.file_name, is_png)
        report.is_screenshot = is_sc
        report.screen_capture_type = sc_type
    else:
        report.is_corrupt_or_truncated = True
        report.anomalies.append("Failed to decode image structure: image data may be corrupted or truncated.")

    return report
