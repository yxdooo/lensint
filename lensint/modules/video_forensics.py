"""Video Forensics Engine: ISOBMFF / MP4 / MOV Parsing, Stego Carving, and GOP Cadence Analysis.

Provides deep forensic inspection for digital video containers (MP4, MOV, MKV, AVI),
detecting trailing C2 stego overlays, editing software footprints, and H.264/H.265
GOP (Group of Pictures) cadence breaks indicating temporal video tampering/splicing.
"""
from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass
class VideoForensicsReport:
    """Represents video forensics structural analysis and GOP cadence results."""
    is_video: bool = False
    container_format: str = "Unknown"
    has_trailing_payload: bool = False
    trailing_payload_size_bytes: int = 0
    atoms_detected: List[Dict[str, Any]] = field(default_factory=list)
    editing_software_footprints: List[str] = field(default_factory=list)
    total_frames_analyzed: int = 0
    gop_structure: List[str] = field(default_factory=list)
    has_gop_cadence_break: bool = False
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


KNOWN_VIDEO_EDITORS = [
    (re.compile(rb"Adobe Premiere", re.IGNORECASE), "Adobe Premiere Pro"),
    (re.compile(rb"DaVinci Resolve", re.IGNORECASE), "Blackmagic DaVinci Resolve"),
    (re.compile(rb"Final Cut Pro|com\.apple\.quicktime", re.IGNORECASE), "Apple Final Cut Pro / QuickTime"),
    (re.compile(rb"Lavf|Lavc", re.IGNORECASE), "FFmpeg Transcoder Library (Lavf/Lavc)"),
    (re.compile(rb"HandBrake", re.IGNORECASE), "HandBrake Video Transcoder"),
    (re.compile(rb"CapCut", re.IGNORECASE), "CapCut Video Editor"),
    (re.compile(rb"Camtasia", re.IGNORECASE), "TechSmith Camtasia Studio"),
]

CONTAINER_ATOM_TYPES = {"moov", "trak", "mdia", "minf", "stbl", "udta"}


def parse_isobmff_atoms(raw_bytes: bytes) -> Tuple[List[Dict[str, Any]], Optional[int], int]:
    """
    Parse ISO Base Media File Format (MP4/MOV) atom box hierarchy.
    Returns: (list_of_atoms, last_atom_end_offset, trailing_payload_bytes).
    """
    atoms = []
    total_len = len(raw_bytes)
    offset = 0
    max_end = 0

    def _parse_boxes(start_offset: int, end_offset: int, depth: int = 0) -> None:
        nonlocal max_end
        cur = start_offset
        while cur + 8 <= end_offset:
            atom_size = int.from_bytes(raw_bytes[cur : cur + 4], "big")
            atom_type = raw_bytes[cur + 4 : cur + 8].decode("latin-1", errors="replace")

            if atom_size == 1 and cur + 16 <= end_offset:
                atom_size = int.from_bytes(raw_bytes[cur + 8 : cur + 16], "big")
                header_size = 16
            elif atom_size == 0:
                atom_size = end_offset - cur
                header_size = 8
            else:
                header_size = 8

            if atom_size < 8:
                break

            atom_end = cur + atom_size
            if atom_end > end_offset:
                break

            if atom_end > max_end:
                max_end = atom_end

            atom_entry = {
                "type": atom_type,
                "offset": cur,
                "size": atom_size,
                "header_size": header_size,
                "depth": depth,
            }
            atoms.append(atom_entry)

            # Recurse into nested container boxes
            if atom_type in CONTAINER_ATOM_TYPES and depth < 3:
                _parse_boxes(cur + header_size, atom_end, depth + 1)

            cur = atom_end

    _parse_boxes(0, total_len, depth=0)
    trailing_size = max(0, total_len - max_end) if max_end > 0 else 0
    return atoms, max_end, trailing_size


def analyze_video_nal_units(raw_bytes: bytes, max_units: int = 1000) -> Tuple[List[str], bool, int]:
    """
    Scan bitstream for H.264/AVC and H.265/HEVC NAL units (supporting both Annex B and AVCC length-prefixed formats).
    Analyzes frame types (I, P, B, SPS, PPS) and evaluates GOP rhythm consistency.
    """
    frame_types = []
    total_len = len(raw_bytes)

    # 1. Annex B scanning (0x000001 or 0x00000001)
    pos = 0
    while pos < total_len - 4 and len(frame_types) < max_units:
        if raw_bytes[pos : pos + 3] == b"\x00\x00\x01":
            nal_byte = raw_bytes[pos + 3]
            pos += 4
        elif raw_bytes[pos : pos + 4] == b"\x00\x00\x00\x01":
            nal_byte = raw_bytes[pos + 4]
            pos += 5
        else:
            pos += 1
            continue

        h264_type = nal_byte & 0x1F
        hevc_type = (nal_byte >> 1) & 0x3F

        if h264_type == 5 or (16 <= hevc_type <= 21):
            frame_types.append("I")
        elif h264_type == 1 or (0 <= hevc_type <= 9):
            frame_types.append("P/B")
        elif h264_type == 7 or hevc_type == 33:
            frame_types.append("SPS")
        elif h264_type == 8 or hevc_type == 34:
            frame_types.append("PPS")

    # 2. AVCC Length-Prefixed scanning inside mdat atom if Annex B found nothing
    if not frame_types:
        mdat_pos = raw_bytes.find(b"mdat")
        if mdat_pos != -1:
            mdat_start = mdat_pos + 4
            cur = mdat_start
            while cur + 4 < total_len and len(frame_types) < max_units:
                nal_len = int.from_bytes(raw_bytes[cur : cur + 4], "big")
                if nal_len <= 0 or cur + 4 + nal_len > total_len:
                    break
                nal_byte = raw_bytes[cur + 4]
                h264_type = nal_byte & 0x1F
                hevc_type = (nal_byte >> 1) & 0x3F

                if h264_type == 5 or (16 <= hevc_type <= 21):
                    frame_types.append("I")
                elif h264_type == 1 or (0 <= hevc_type <= 9):
                    frame_types.append("P/B")
                elif h264_type == 7 or hevc_type == 33:
                    frame_types.append("SPS")
                elif h264_type == 8 or hevc_type == 34:
                    frame_types.append("PPS")

                cur += 4 + nal_len

    # GOP Cadence regularity check (Interval between 'I' keyframes)
    i_indices = [idx for idx, t in enumerate(frame_types) if t == "I"]
    cadence_break = False
    if len(i_indices) >= 3:
        gop_lengths = [i_indices[k] - i_indices[k - 1] for k in range(1, len(i_indices))]
        mean_gop = sum(gop_lengths) / len(gop_lengths)
        std_gop = (sum((x - mean_gop) ** 2 for x in gop_lengths) / len(gop_lengths)) ** 0.5
        # Standard camera recorders maintain fixed GOP size (e.g. 15, 30, 60). Large variance indicates editing/cuts
        if std_gop > 4.0:
            cadence_break = True

    return frame_types, cadence_break, len(frame_types)


def analyze_video_forensics(raw_bytes: bytes) -> VideoForensicsReport:
    """Perform full structural container and temporal GOP tampering analysis on video bytes."""
    rep = VideoForensicsReport()
    total_len = len(raw_bytes)
    if total_len < 16:
        return rep

    # Detect container format
    if raw_bytes[4:8] == b"ftyp" or raw_bytes[4:8] == b"moov":
        rep.is_video = True
        rep.container_format = "MP4 / ISO QuickTime Container (ISOBMFF)"
    elif raw_bytes.startswith(b"\x1a\x45\xdf\xa3"):
        rep.is_video = True
        rep.container_format = "Matroska / WebM Video Container (MKV)"
    elif raw_bytes.startswith(b"RIFF") and raw_bytes[8:12] == b"AVI ":
        rep.is_video = True
        rep.container_format = "Audio Video Interleave Container (AVI)"

    if not rep.is_video:
        return rep

    # 1. Inspect editing software signatures across head and tail buffers
    scan_chunk = raw_bytes[:min(total_len, 2_000_000)]
    if total_len > 2_000_000:
        scan_chunk += raw_bytes[-2_000_000:]

    for pattern, name in KNOWN_VIDEO_EDITORS:
        if pattern.search(scan_chunk):
            if name not in rep.editing_software_footprints:
                rep.editing_software_footprints.append(name)
                rep.findings.append(f"Video editing software footprint detected: {name}.")

    # 2. ISOBMFF Atom parsing
    if "ISOBMFF" in rep.container_format:
        atoms, max_end, trailing_size = parse_isobmff_atoms(raw_bytes)
        rep.atoms_detected = atoms[:30]
        if trailing_size > 0:
            rep.has_trailing_payload = True
            rep.trailing_payload_size_bytes = trailing_size
            rep.findings.append(
                f"Trailing video overlay data discovered: {trailing_size} bytes appended beyond container boundary (Offset: 0x{max_end:X})."
            )

    # 3. NAL Bitstream & GOP Splicing Analysis
    frames, cadence_break, frame_count = analyze_video_nal_units(raw_bytes)
    rep.total_frames_analyzed = frame_count
    rep.gop_structure = frames[:30]
    rep.has_gop_cadence_break = cadence_break

    if cadence_break:
        rep.findings.append(
            "Temporal GOP Cadence Break detected: Irregular keyframe (I-frame) spacing indicates video cut/splice or spliced scene insertion."
        )

    return rep
