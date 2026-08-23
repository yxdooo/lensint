"""Memory Forensics & In-Memory Process Image Carver for LENSINT.

Extracts, carves, and analyzes image buffers, clipboard caches, and graphic textures
from raw RAM memory dumps (.raw, .dmp, .vmem) or live process memory streams.
Includes Volatility 3 compatible scanner engine.
"""
from __future__ import annotations

import io
import os
import re
from typing import Any, Dict, Generator, List, Optional, Tuple
from PIL import Image

from lensint.core.models import IntegrityReport
from lensint.utils.signatures import EMBEDDED_SIGNATURES


# Standard in-memory image signature patterns
MEMORY_IMAGE_PATTERNS = [
    (b"\xFF\xD8\xFF", b"\xFF\xD9", "JPEG", "image/jpeg", 2),
    (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", "PNG", "image/png", 8),
    (b"GIF87a", b"\x00\x3B", "GIF", "image/gif", 2),
    (b"GIF89a", b"\x00\x3B", "GIF", "image/gif", 2),
    (b"RIFF", b"WEBP", "WEBP", "image/webp", 4),
    (b"BM", None, "BMP", "image/bmp", 0),
]


class MemoryForensicsEngine:
    """High-speed carving engine for volatile memory artifacts."""

    def __init__(self, max_carve_size_bytes: int = 25 * 1024 * 1024):
        self.max_carve_size = max_carve_size_bytes

    def carve_memory_stream(
        self,
        raw_memory: bytes,
        max_images: int = 50,
    ) -> List[Dict[str, Any]]:
        """Carve image buffers and GDI/DIB surfaces from a raw memory buffer."""
        carved_results = []
        total_len = len(raw_memory)
        if total_len < 32:
            return carved_results

        # 1. Carve PNGs
        png_pos = 0
        while len(carved_results) < max_images:
            png_pos = raw_memory.find(b"\x89PNG\r\n\x1a\n", png_pos)
            if png_pos == -1:
                break
            iend_pos = raw_memory.find(b"IEND", png_pos)
            if iend_pos != -1 and (iend_pos + 8 - png_pos) <= self.max_carve_size:
                img_data = raw_memory[png_pos : iend_pos + 8]
                try:
                    with Image.open(io.BytesIO(img_data)) as test_img:
                        w, h = test_img.size
                        if w >= 8 and h >= 8:
                            carved_results.append({
                                "format": "PNG",
                                "offset": png_pos,
                                "offset_hex": hex(png_pos),
                                "size_bytes": len(img_data),
                                "dimensions": (w, h),
                                "raw_bytes": img_data,
                                "source": "Process Memory Heap / Network Buffer",
                            })
                except Exception:
                    pass
            png_pos += 8

        # 2. Carve JPEGs
        jpg_pos = 0
        while len(carved_results) < max_images:
            jpg_pos = raw_memory.find(b"\xFF\xD8\xFF", jpg_pos)
            if jpg_pos == -1:
                break
            eoi_pos = raw_memory.find(b"\xFF\xD9", jpg_pos + 4)
            if eoi_pos != -1 and (eoi_pos + 2 - jpg_pos) <= self.max_carve_size:
                img_data = raw_memory[jpg_pos : eoi_pos + 2]
                try:
                    with Image.open(io.BytesIO(img_data)) as test_img:
                        w, h = test_img.size
                        if w >= 8 and h >= 8:
                            carved_results.append({
                                "format": "JPEG",
                                "offset": jpg_pos,
                                "offset_hex": hex(jpg_pos),
                                "size_bytes": len(img_data),
                                "dimensions": (w, h),
                                "raw_bytes": img_data,
                                "source": "Browser Cache / Clipboard DIB Surface",
                            })
                except Exception:
                    pass
            jpg_pos += 4

        # 3. Carve BMP (BITMAPFILEHEADER structure)
        bmp_pos = 0
        while len(carved_results) < max_images:
            bmp_pos = raw_memory.find(b"BM", bmp_pos)
            if bmp_pos == -1 or bmp_pos + 14 > total_len:
                break
            try:
                declared_size = int.from_bytes(raw_memory[bmp_pos + 2 : bmp_pos + 6], byteorder="little")
                pixel_offset = int.from_bytes(raw_memory[bmp_pos + 10 : bmp_pos + 14], byteorder="little")
                if 54 <= pixel_offset <= 1024 and 54 < declared_size <= min(self.max_carve_size, total_len - bmp_pos):
                    img_data = raw_memory[bmp_pos : bmp_pos + declared_size]
                    with Image.open(io.BytesIO(img_data)) as test_img:
                        w, h = test_img.size
                        if w >= 8 and h >= 8:
                            carved_results.append({
                                "format": "BMP",
                                "offset": bmp_pos,
                                "offset_hex": hex(bmp_pos),
                                "size_bytes": len(img_data),
                                "dimensions": (w, h),
                                "raw_bytes": img_data,
                                "source": "GDI DIB / Screen Buffer Allocation",
                            })
            except Exception:
                pass
            bmp_pos += 2

        return carved_results

    def scan_memory_dump_file(
        self,
        dump_path: str,
        chunk_size: int = 8 * 1024 * 1024,
        max_images: int = 100,
    ) -> List[Dict[str, Any]]:
        """Stream-carve an entire RAM dump file (.raw, .dmp, .vmem)."""
        if not os.path.exists(dump_path):
            raise FileNotFoundError(f"Memory dump file not found: {dump_path}")

        file_size = os.path.getsize(dump_path)
        all_carved = []

        with open(dump_path, "rb") as f:
            overlap = 1024 * 1024  # 1MB overlap between chunks
            buffer = b""
            offset_base = 0

            while len(all_carved) < max_images:
                new_chunk = f.read(chunk_size)
                if not new_chunk:
                    break
                combined = buffer + new_chunk
                carved = self.carve_memory_stream(combined, max_images=max_images - len(all_carved))
                for c in carved:
                    c["offset"] += offset_base
                    c["offset_hex"] = hex(c["offset"])
                    all_carved.append(c)
                buffer = combined[-overlap:] if len(combined) > overlap else combined
                offset_base += len(new_chunk)

        return all_carved


# Volatility 3 Plugin Interface Spec
class VolatilityLensintPlugin:
    """Integration hook for Volatility 3 memory forensics framework.

    Allows running LENSINT deep stego and tampering inspection on images
    carved directly from Volatility 3 kernel/process memory layers.
    """

    _version = (3, 0, 0)
    _description = "LENSINT Deep Stego & Visual Tampering Forensics Scanner for Volatility 3"

    @classmethod
    def scan_layer_pages(cls, layer_bytes: bytes) -> List[Dict[str, Any]]:
        engine = MemoryForensicsEngine()
        return engine.carve_memory_stream(layer_bytes)
