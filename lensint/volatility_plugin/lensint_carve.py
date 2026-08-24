"""Volatility 3 Memory Forensics Plugin for LENSINT.

Plugin Name: windows.lensint_carve
Scans process virtual address descriptors (VADs), memory mapped sections, and heap
for uncommitted GDI/DIB graphic surfaces, embedded PNG/JPEG/WEBP/GIF images, and in-memory
C2 steganography carriers extracted from volatile physical memory dumps.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    from volatility3.framework import exceptions, interfaces, renderers
    from volatility3.framework.configuration import requirements
    from volatility3.framework.interfaces import plugins
    from volatility3.plugins.windows import pslist
    VOLATILITY_AVAILABLE = True
except ImportError:
    VOLATILITY_AVAILABLE = False


class LensintCarvePlugin:
    """
    Volatility 3 Custom Plugin implementation for in-memory image carving and C2 stego analysis.
    Works inside Volatility 3 framework or standalone in memory forensics pipelines.
    """
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        if not VOLATILITY_AVAILABLE:
            return []
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist",
                plugin=pslist.PsList,
                version=(2, 0, 0),
            ),
            requirements.IntRequirement(
                name="pid",
                description="Specific Process ID to carve (optional)",
                optional=True,
            ),
        ]

    def run_carve_on_buffer(self, buffer_bytes: bytes, max_images: int = 100) -> List[Dict[str, Any]]:
        """
        Standalone memory carver leveraging LENSINT's multi-format structural carvers.
        """
        from lensint.modules.memory_forensics import carve_memory_artifacts
        results = carve_memory_artifacts(buffer_bytes, max_carved_items=max_images)
        carved_list = []
        for item in results.get("carved_images", []):
            carved_list.append({
                "format": item.get("format"),
                "offset_hex": item.get("offset_hex"),
                "size_bytes": item.get("size_bytes"),
                "entropy": item.get("entropy"),
                "sha256": item.get("sha256"),
            })
        return carved_list
