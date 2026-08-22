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
