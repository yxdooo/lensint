"""
Image decoding, array transformations, and base64 rendering helpers.
"""

import base64
import io
import os
from typing import Optional, Tuple
import numpy as np
from PIL import Image


def format_bytes(size: int) -> str:
    """Format bytes into human readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024.0:
            return f"{size:3.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def load_image_safe(file_path: str) -> Tuple[Optional[Image.Image], Optional[bytes], Optional[str]]:
    """
    Safely load an image file and raw bytes.
    Returns (PIL.Image, raw_bytes, error_message).
    """
    if not os.path.exists(file_path):
        return None, None, f"File not found: {file_path}"

    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        img = Image.open(io.BytesIO(raw_bytes))
        img.load()
        return img, raw_bytes, None
    except Exception as e:
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
            return None, raw_bytes, f"Image decoder warning: {str(e)}"
        except Exception as read_err:
            return None, None, f"File read error: {str(read_err)}"


def image_to_base64(img: Image.Image, format_name: str = "PNG") -> str:
    """Encode a PIL Image object to a base64 Data URI."""
    buf = io.BytesIO()
    if format_name.upper() == "JPEG" and img.mode in ("RGBA", "P"):
        img = img.convert("RGB")
    img.save(buf, format=format_name)
    b64_data = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/{format_name.lower()};base64,{b64_data}"


def numpy_to_base64_png(arr: np.ndarray) -> str:
    """Convert numpy array (uint8) to base64 PNG data URI."""
    if arr.dtype != np.uint8:
        arr = np.clip(arr, 0, 255).astype(np.uint8)

    if len(arr.shape) == 2:
        img = Image.fromarray(arr, mode="L")
    elif len(arr.shape) == 3:
        if arr.shape[2] == 3:
            img = Image.fromarray(arr, mode="RGB")
        elif arr.shape[2] == 4:
            img = Image.fromarray(arr, mode="RGBA")
        else:
            img = Image.fromarray(arr[:, :, 0], mode="L")
    else:
        raise ValueError(f"Unsupported array shape: {arr.shape}")

    return image_to_base64(img, "PNG")


def downsample_for_analysis(pil_img: Image.Image, max_pixels: int = 4_000_000,
                             max_side: int = 2000) -> Tuple[Image.Image, bool]:
    """Downsample large images before expensive pixel-level analysis.

    Returns the (possibly downsampled) image and a boolean indicating
    whether downsampling was applied.  The caller should use this for
    analysis only — the original image is not modified.

    Args:
        pil_img:    Source PIL image.
        max_pixels: Maximum total pixel count before downsampling triggers.
        max_side:   Maximum length of the longer side after downsampling.

    Returns:
        (image, was_downsampled)
    """
    w, h = pil_img.size
    if w * h <= max_pixels:
        return pil_img, False

    scale = min(max_side / max(w, h), 1.0)
    new_w = max(1, int(w * scale))
    new_h = max(1, int(h * scale))
    return pil_img.resize((new_w, new_h), Image.LANCZOS), True


def heatmap_to_base64(values: np.ndarray, scale: int = 4) -> str:
    """Convert a 2-D float array to a false-colour heatmap PNG data URI.

    Colour mapping (normalised 0-1):
        0.0 – 0.33  → blue  (low)
        0.33 – 0.66 → green (medium)
        0.66 – 1.0  → red   (high)

    Args:
        values: 2-D numpy array of floats.
        scale:  Integer zoom factor applied before encoding.

    Returns:
        Base-64 encoded PNG data URI string.
    """
    if values.size == 0:
        return ""

    norm = (values - values.min()) / max(values.max() - values.min(), 1e-9)
    h, w = norm.shape
    rgb = np.zeros((h, w, 3), dtype=np.uint8)

    low = norm < 0.33
    mid = (norm >= 0.33) & (norm < 0.66)
    high = norm >= 0.66

    # Blue range
    t_low = norm[low] / 0.33
    rgb[low, 2] = 255
    rgb[low, 1] = (t_low * 100).astype(np.uint8)

    # Green range
    t_mid = (norm[mid] - 0.33) / 0.33
    rgb[mid, 1] = 200
    rgb[mid, 0] = (t_mid * 100).astype(np.uint8)
    rgb[mid, 2] = ((1 - t_mid) * 100).astype(np.uint8)

    # Red range
    t_high = (norm[high] - 0.66) / 0.34
    rgb[high, 0] = 255
    rgb[high, 1] = ((1 - t_high) * 80).astype(np.uint8)

    img = Image.fromarray(rgb, mode="RGB")
    if scale > 1:
        img = img.resize((w * scale, h * scale), Image.NEAREST)

    return image_to_base64(img, "PNG")

