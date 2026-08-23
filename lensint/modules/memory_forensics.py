"""Memory Forensics & In-Memory Process Image Carver for LENSINT.

Extracts, carves, and analyzes image buffers, clipboard caches, and graphic textures
from raw RAM memory dumps (.raw, .dmp, .vmem) or live process memory streams.
"""
from __future__ import annotations

import io
import os
import struct
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

        all_candidates: List[Dict[str, Any]] = []

        # 1. Carve PNGs structurally
        png_pos = 0
        import zlib
        while True:
            png_pos = raw_memory.find(b"\x89PNG\r\n\x1a\n", png_pos)
            if png_pos == -1:
                break
            
            cur = png_pos + 8
            valid = True
            while cur < total_len and cur - png_pos < self.max_carve_size:
                if cur + 12 > total_len:
                    valid = False
                    break
                length = int.from_bytes(raw_memory[cur : cur + 4], "big")
                if length > self.max_carve_size or cur + 12 + length > total_len:
                    valid = False
                    break
                
                chunk_type = raw_memory[cur + 4 : cur + 8]
                chunk_data = raw_memory[cur + 8 : cur + 8 + length]
                expected_crc = int.from_bytes(raw_memory[cur + 8 + length : cur + 12 + length], "big")
                
                calculated_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
                if calculated_crc != expected_crc:
                    valid = False
                    break

                cur += 12 + length
                if chunk_type == b"IEND":
                    break

            if valid and cur <= total_len:
                img_data = raw_memory[png_pos : cur]
                try:
                    with Image.open(io.BytesIO(img_data)) as test_img:
                        w, h = test_img.size
                        if w >= 8 and h >= 8:
                            all_candidates.append({
                                "format": "PNG",
                                "offset": png_pos,
                                "offset_hex": hex(png_pos),
                                "size_bytes": len(img_data),
                                "dimensions": (w, h),
                                "raw_bytes": img_data,
                                "source": f"Memory Carved Chunk (Offset: {hex(png_pos)})",
                            })
                except Exception:
                    pass
            png_pos += 8

        # 2. Carve JPEGs structurally (Marker Jumping)
        jpg_pos = 0
        while True:
            jpg_pos = raw_memory.find(b"\xFF\xD8\xFF", jpg_pos)
            if jpg_pos == -1:
                break
            
            cur = jpg_pos + 2
            found_eoi = False
            
            while cur < total_len - 1 and cur - jpg_pos < self.max_carve_size:
                if raw_memory[cur] != 0xFF:
                    cur += 1
                    continue
                    
                marker = raw_memory[cur + 1]
                if marker == 0xD9:  # EOI
                    cur += 2
                    found_eoi = True
                    break
                elif marker == 0x00 or (0xD0 <= marker <= 0xD7):
                    cur += 2
                elif marker == 0xDA:  # SOS
                    if cur + 4 > total_len:
                        break
                    length = int.from_bytes(raw_memory[cur + 2 : cur + 4], "big")
                    cur += 2 + length
                    while cur < total_len - 1 and (cur - jpg_pos) < self.max_carve_size:
                        if raw_memory[cur] == 0xFF and raw_memory[cur + 1] != 0x00 and not (0xD0 <= raw_memory[cur + 1] <= 0xD7):
                            break
                        cur += 1
                else:
                    if cur + 4 > total_len:
                        break
                    length = int.from_bytes(raw_memory[cur + 2 : cur + 4], "big")
                    cur += 2 + length

            if found_eoi and cur <= total_len:
                img_data = raw_memory[jpg_pos : cur]
                try:
                    with Image.open(io.BytesIO(img_data)) as test_img:
                        test_img.load()
                        w, h = test_img.size
                        if w >= 8 and h >= 8:
                            all_candidates.append({
                                "format": "JPEG",
                                "offset": jpg_pos,
                                "offset_hex": hex(jpg_pos),
                                "size_bytes": len(img_data),
                                "dimensions": (w, h),
                                "raw_bytes": img_data,
                                "source": f"Memory Carved Chunk (Offset: {hex(jpg_pos)})",
                            })
                except Exception:
                    pass
            jpg_pos += 4

        # 3. Carve WEBP structurally (RIFF + size + WEBP)
        webp_pos = 0
        while True:
            webp_pos = raw_memory.find(b"RIFF", webp_pos)
            if webp_pos == -1 or webp_pos + 12 > total_len:
                break
            
            if raw_memory[webp_pos + 8 : webp_pos + 12] == b"WEBP":
                declared_size = int.from_bytes(raw_memory[webp_pos + 4 : webp_pos + 8], "little")
                total_size = declared_size + 8
                if 16 <= total_size <= self.max_carve_size and webp_pos + total_size <= total_len:
                    img_data = raw_memory[webp_pos : webp_pos + total_size]
                    try:
                        with Image.open(io.BytesIO(img_data)) as test_img:
                            w, h = test_img.size
                            if w >= 8 and h >= 8:
                                all_candidates.append({
                                    "format": "WEBP",
                                    "offset": webp_pos,
                                    "offset_hex": hex(webp_pos),
                                    "size_bytes": len(img_data),
                                    "dimensions": (w, h),
                                    "raw_bytes": img_data,
                                    "source": f"Memory Carved Chunk (Offset: {hex(webp_pos)})",
                                })
                    except Exception:
                        pass
            webp_pos += 4

        # 4. Carve GIF structurally (GIF87a / GIF89a -> ... -> \x3B)
        for magic in (b"GIF87a", b"GIF89a"):
            gif_pos = 0
            while True:
                gif_pos = raw_memory.find(magic, gif_pos)
                if gif_pos == -1:
                    break
                
                trailer_pos = raw_memory.find(b"\x3B", gif_pos + 6)
                while trailer_pos != -1 and (trailer_pos - gif_pos) < self.max_carve_size:
                    img_data = raw_memory[gif_pos : trailer_pos + 1]
                    try:
                        with Image.open(io.BytesIO(img_data)) as test_img:
                            w, h = test_img.size
                            if w >= 8 and h >= 8:
                                all_candidates.append({
                                    "format": "GIF",
                                    "offset": gif_pos,
                                    "offset_hex": hex(gif_pos),
                                    "size_bytes": len(img_data),
                                    "dimensions": (w, h),
                                    "raw_bytes": img_data,
                                    "source": f"Memory Carved Chunk (Offset: {hex(gif_pos)})",
                                })
                                break
                    except Exception:
                        pass
                    trailer_pos = raw_memory.find(b"\x3B", trailer_pos + 1)
                gif_pos += 6

        # 5. Carve BMP (BITMAPFILEHEADER structure)
        bmp_pos = 0
        while True:
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
                            all_candidates.append({
                                "format": "BMP",
                                "offset": bmp_pos,
                                "offset_hex": hex(bmp_pos),
                                "size_bytes": len(img_data),
                                "dimensions": (w, h),
                                "raw_bytes": img_data,
                                "source": f"Memory Carved Chunk (Offset: {hex(bmp_pos)})",
                            })
            except Exception:
                pass
            bmp_pos += 2

        # Sort all candidates by offset and limit to max_images
        all_candidates.sort(key=lambda c: c["offset"])
        return all_candidates[:max_images]

    def scan_memory_dump_file(
        self,
        dump_path: str,
        chunk_size: int = 8 * 1024 * 1024,
        max_images: int = 100,
    ) -> List[Dict[str, Any]]:
        """Stream-carve an entire RAM dump file (.raw, .dmp, .vmem)."""
        if not os.path.exists(dump_path):
            raise FileNotFoundError(f"Memory dump file not found: {dump_path}")

        import hashlib
        all_carved = []
        seen_payloads = set()
        
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
                    # buffer contains bytes from the END of the previous chunk.
                    # so the current 'combined' string starts at offset_base - len(buffer)
                    absolute_offset = c["offset"] + offset_base - len(buffer)
                    payload_hash = hashlib.sha256(c["raw_bytes"]).hexdigest()
                    if payload_hash not in seen_payloads:
                        c["offset"] = absolute_offset
                        c["offset_hex"] = hex(absolute_offset)
                        all_carved.append(c)
                        seen_payloads.add(payload_hash)
                
                buffer = combined[-overlap:] if len(combined) > overlap else combined
                offset_base += len(new_chunk)

        return all_carved
