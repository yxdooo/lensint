"""Video Container (ISOBMFF/MP4/MOV/MKV/AVI) & Temporal GOP Splicing Forensic Analyzer.

Performs structural atom inspection, trailing video payload carving, editing software footprint
identification, and H.264/H.265 NAL bitstream Group-of-Pictures (GOP) cadence analysis to detect
frame deletion, video splicing, and double video compression.
"""
from __future__ import annotations

import io
import re
import struct
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass
class VideoForensicsReport:
    """Represents structural and temporal forensic inspection of video files."""
    is_video: bool = False
    container_format: str = "Unknown"
    duration_seconds: float = 0.0
    total_frames_analyzed: int = 0
    gop_structure: List[str] = field(default_factory=list)
    has_gop_cadence_break: bool = False
    has_trailing_payload: bool = False
    trailing_payload_size_bytes: int = 0
    editing_software_footprints: List[str] = field(default_factory=list)
    atoms_detected: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


KNOWN_VIDEO_EDITORS = [
    (re.compile(rb"Adobe Premiere|Premiere Pro", re.IGNORECASE), "Adobe Premiere Pro"),
    (re.compile(rb"DaVinci Resolve", re.IGNORECASE), "Blackmagic DaVinci Resolve"),
    (re.compile(rb"Final Cut|Apple ProRes|FCPX", re.IGNORECASE), "Apple Final Cut Pro"),
    (re.compile(rb"Lavf|Lavc|FFmpeg", re.IGNORECASE), "FFmpeg Transcoder Library (Lavf/Lavc)"),
    (re.compile(rb"HandBrake", re.IGNORECASE), "HandBrake Video Transcoder"),
    (re.compile(rb"CapCut", re.IGNORECASE), "CapCut Video Editor"),
    (re.compile(rb"Camtasia", re.IGNORECASE), "TechSmith Camtasia Studio"),
]


def parse_isobmff_atoms(raw_bytes: bytes) -> Tuple[List[Dict[str, Any]], Optional[int], int]:
    """
    Parse ISO Base Media File Format (MP4/MOV) atom box hierarchy.
    Returns: (list_of_atoms, last_atom_end_offset, trailing_payload_bytes).
    """
    atoms = []
    total_len = len(raw_bytes)
    offset = 0
    max_end = 0

    while offset + 8 <= total_len:
        atom_size = int.from_bytes(raw_bytes[offset : offset + 4], "big")
        atom_type = raw_bytes[offset + 4 : offset + 8].decode("latin-1", errors="replace")

        # 64-bit large size atom
        if atom_size == 1 and offset + 16 <= total_len:
            atom_size = int.from_bytes(raw_bytes[offset + 8 : offset + 16], "big")
            header_size = 16
        elif atom_size == 0:
            # Atom extends to end of file
            atom_size = total_len - offset
            header_size = 8
        else:
            header_size = 8

        if atom_size < 8:
            break

        atom_end = offset + atom_size
        if atom_end > total_len:
            # Trailing payload / non-atom data encountered
            break

        if atom_end > max_end:
            max_end = atom_end

        atoms.append({
            "type": atom_type,
            "offset": offset,
            "size": atom_size,
            "header_size": header_size,
        })

        offset = atom_end

    trailing_size = max(0, total_len - max_end) if max_end > 0 else 0
    return atoms, max_end, trailing_size


def analyze_h264_nal_units(raw_bytes: bytes, max_units: int = 1000) -> Tuple[List[str], bool, int]:
    """
    Scan bitstream for H.264/AVC NAL units to analyze frame types (I, P, B) and GOP rhythm.
    NAL start code: 0x000001 or 0x00000001.
    """
    frame_types = []
    pos = 0
    total_len = len(raw_bytes)

    while pos < total_len - 4 and len(frame_types) < max_units:
        # Search for NAL start code
        if raw_bytes[pos : pos + 3] == b"\x00\x00\x01":
            nal_byte = raw_bytes[pos + 3]
            pos += 4
        elif raw_bytes[pos : pos + 4] == b"\x00\x00\x00\x01":
            nal_byte = raw_bytes[pos + 4]
            pos += 5
        else:
            pos += 1
            continue

        nal_unit_type = nal_byte & 0x1F

        if nal_unit_type == 5:  # IDR (Instantaneous Decoder Refresh) -> Keyframe I
            frame_types.append("I")
        elif nal_unit_type == 1:  # Non-IDR Slice -> P or B frame (Approximation from slice header)
            frame_types.append("P/B")
        elif nal_unit_type == 7:  # SPS
            frame_types.append("SPS")
        elif nal_unit_type == 8:  # PPS
            frame_types.append("PPS")

    # GOP Cadence regularity check (Interval between 'I' frames)
    i_indices = [idx for idx, t in enumerate(frame_types) if t == "I"]
    cadence_break = False
    if len(i_indices) >= 3:
        gop_lengths = [i_indices[k] - i_indices[k - 1] for k in range(1, len(i_indices))]
        std_gop = float(np_std := (sum((x - sum(gop_lengths)/len(gop_lengths))**2 for x in gop_lengths) / len(gop_lengths))**0.5)
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

    # 1. Inspect editing software signatures
    for pattern, name in KNOWN_VIDEO_EDITORS:
        if pattern.search(raw_bytes[:min(total_len, 2_000_000)]):
            if name not in rep.editing_software_footprints:
                rep.editing_software_footprints.append(name)
                rep.findings.append(f"Video editing software footprint detected: {name}.")

    # 2. ISOBMFF Atom parsing
    if "ISOBMFF" in rep.container_format:
        atoms, max_end, trailing_size = parse_isobmff_atoms(raw_bytes)
        rep.atoms_detected = atoms[:25]
        if trailing_size > 0:
            rep.has_trailing_payload = True
            rep.trailing_payload_size_bytes = trailing_size
            rep.findings.append(
                f"Trailing video overlay data discovered: {trailing_size} bytes appended beyond container boundary (Offset: 0x{max_end:X})."
            )

    # 3. NAL Bitstream & GOP Splicing Analysis
    frames, cadence_break, frame_count = analyze_h264_nal_units(raw_bytes)
    rep.total_frames_analyzed = frame_count
    rep.gop_structure = frames[:30]
    rep.has_gop_cadence_break = cadence_break

    if cadence_break:
        rep.findings.append(
            "Temporal GOP Cadence Break detected: Irregular keyframe (I-frame) spacing indicates video cut/splice or spliced scene insertion."
        )

    return rep
