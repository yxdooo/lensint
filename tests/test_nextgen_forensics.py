"""Comprehensive Unit & Forensic Verification Suite for LENSINT Next-Generation Modules.

Tests:
1. C2PA / JUMBF Manifest Store, CBOR/COSE Sign1, and Anti-Forensics Stripping Detection.
2. Biometric rPPG (CHROM/POS Pulse), Cross-Region Coherence, EAR Poisson Blinking, & Deepfake Scoring.
3. Sensor Dust Invariant Mapping, Bipartite Camera Ballistics Matching, & Brown-Conrady Distortion.
4. Spatial Rich Model (SRM) 30 Sub-models, S-UNIWARD/WOW/HILL Steganalysis, & Steghide/OpenPuff.
5. PCAP/PCAPNG Packet Parser, TCP Stream Reassembly State Machine, & Automated Media Carving.
"""
from __future__ import annotations

import io
import math
import struct
import numpy as np
from PIL import Image
import pytest

from lensint.modules.c2pa_manifest import (
    analyze_c2pa_manifest,
    parse_jumbf_hierarchy,
    PureCBORDecoder,
    decode_cbor_safe,
    C2PAManifestReport,
)
from lensint.modules.biometrics_rppg import (
    analyze_biometrics_rppg,
    compute_chrom_pulse,
    compute_pos_pulse,
    compute_psd_snr,
    compute_cross_region_coherence,
    estimate_ear_and_blinks,
    evaluate_corneal_specular_reflection,
    BiometricsRPPGReport,
)
from lensint.modules.optics_dust import (
    analyze_optics_and_dust,
    match_sensor_dust,
    extract_sensor_dust_spots,
    estimate_brown_conrady_distortion,
    SensorDustReport,
    DustMatchResult,
    DustSpot,
)
from lensint.modules.neural_stego import (
    analyze_neural_stego,
    build_srm_filter_bank,
    evaluate_srm_filter_bank,
    scan_steghide_anomaly,
    scan_openpuff_and_bitplanes,
    NeuralStegoReport,
)
from lensint.modules.pcap_stream import (
    analyze_pcap_stream,
    parse_pcap_packets,
    decode_link_layer_frame,
    TCPStreamReassembler,
    carve_images_from_raw_stream,
    PCAPStreamReport,
)


# ==============================================================================
# 1. C2PA / JUMBF MANIFEST TESTS
# ==============================================================================

class TestC2PAManifestModule:
    """Tests for C2PA provenance, JUMBF box hierarchy, and anti-forensics detection."""

    def test_pure_cbor_decoder_primitives(self):
        """Tests pure Python CBOR decoding for numbers, strings, maps, and arrays."""
        # CBOR for {"key": "value", "num": 42, "neg": -10, "arr": [True, False, None]}
        # Handcraft or test individual CBOR bytes
        # uint 42: 0x18, 0x2a
        d1 = PureCBORDecoder(bytes([0x18, 0x2A])).decode()
        assert d1 == 42

        # negint -10: 0x29 (major 1, value 9 => -1 - 9 = -10)
        d2 = PureCBORDecoder(bytes([0x29])).decode()
        assert d2 == -10

        # text string "hello": 0x65, 'h','e','l','l','o'
        d3 = PureCBORDecoder(b"\x65hello").decode()
        assert d3 == "hello"

        # array [1, 2, 3]: 0x83, 0x01, 0x02, 0x03
        d4 = PureCBORDecoder(bytes([0x83, 0x01, 0x02, 0x03])).decode()
        assert d4 == [1, 2, 3]

        # map {"a": 1}: 0xa1, 0x61, 'a', 0x01
        d5 = PureCBORDecoder(b"\xa1\x61a\x01").decode()
        assert d5 == {"a": 1}

    def test_jumbf_box_parsing_and_manifest_extraction(self):
        """Tests recursive JUMBF superbox parsing and C2PA claim assertion extraction."""
        # Construct synthetic JUMBF Superbox 'jumb' containing 'jumd' and content box
        # Box 1: 'jumd' (Description Box)
        # Type UUID (16 bytes) + Toggles (1 byte: label present = 0x02) + Label ("c2pa.claim\x00")
        uuid_16 = bytes.fromhex("6332636c00110010800000aa00389b71")
        jumd_payload = uuid_16 + b"\x02" + b"c2pa.claim\x00"
        jumd_len = 8 + len(jumd_payload)
        jumd_box = struct.pack(">I", jumd_len) + b"jumd" + jumd_payload

        # Box 2: CBOR payload containing claim dict
        # {"claim_generator": "Adobe Photoshop 2024", "title": "Courtroom Asset #101", "instance_id": "urn:uuid:1234"}
        claim_dict = {
            "claim_generator": "Adobe Photoshop 2024",
            "title": "Courtroom Asset #101",
            "instance_id": "urn:uuid:1234",
            "assertions": [
                {"url": "c2pa.actions", "hash": b"\xaa" * 32},
            ]
        }
        # Encode with CBOR or pure mapping
        try:
            import cbor2
            claim_cbor = cbor2.dumps(claim_dict)
        except ImportError:
            # Fallback simple CBOR bytes (claim_generator: 15=0x6f, val: 20=0x74, title: 5=0x65, val: 20=0x74, instance_id: 11=0x6b, val: 13=0x6d)
            claim_cbor = b"\xa3\x6fclaim_generator\x74Adobe Photoshop 2024\x65title\x74Courtroom Asset #101\x6binstance_id\x6durn:uuid:1234"

        cbor_box_len = 8 + len(claim_cbor)
        cbor_box = struct.pack(">I", cbor_box_len) + b"cbor" + claim_cbor

        # Superbox 'jumb'
        super_len = 8 + len(jumd_box) + len(cbor_box)
        superbox = struct.pack(">I", super_len) + b"jumb" + jumd_box + cbor_box

        # Parse JUMBF hierarchy
        boxes = parse_jumbf_hierarchy(superbox)
        assert len(boxes) >= 1
        assert boxes[0].box_type == "jumb"
        assert boxes[0].label == "c2pa.claim"
        assert len(boxes[0].child_boxes) >= 1

        # Wrap into synthetic JPEG APP11 marker
        app11_marker = b"\xFF\xD8\xFF\xEB" + struct.pack(">H", 2 + 4 + len(superbox)) + b"JP\x00\x00" + superbox + b"\xFF\xD9"
        rep = analyze_c2pa_manifest(app11_marker)
        assert rep.has_c2pa_manifest is True
        assert rep.is_valid_c2pa is True
        assert rep.claim_generator == "Adobe Photoshop 2024"
        assert rep.title == "Courtroom Asset #101"

    def test_c2pa_anti_forensics_stripped_manifest_detection(self):
        """Tests detection of stripped C2PA metadata in images with XMP traces but no JUMBF container."""
        # Create JPEG containing XMP provenance trace without APP11 JUMBF box
        jpeg_with_xmp_trace = (
            b"\xFF\xD8\xFF\xE1\x00\x60http://ns.adobe.com/xap/1.0/\x00"
            b"<x:xmpmeta xmlns:x='adobe:ns:meta/'><rdf:RDF xmlns:c2pa='http://c2pa.org/manifest/'>"
            b"<dc:provenance>urn:c2pa:manifest:12345</dc:provenance></rdf:RDF></x:xmpmeta>"
            b"\xFF\xD9"
        )

        rep = analyze_c2pa_manifest(jpeg_with_xmp_trace)
        assert rep.has_c2pa_manifest is False
        assert rep.manifest_stripped_detected is True
        assert len(rep.anti_forensics_warnings) > 0
        assert any("Manifest Stripped" in f for f in rep.findings)


# ==============================================================================
# 2. BIOMETRIC rPPG & VIDEO DEEPFAKE TESTS
# ==============================================================================

class TestBiometricsRPPGModule:
    """Tests for rPPG pulse extraction, cross-region coherence, and deepfake verification."""

    def test_chrom_and_pos_pulse_extraction_synthetic_bvp(self):
        """Tests CHROM and POS pulse waveform recovery from synthetic rhythmic color variations."""
        fps = 30.0
        duration_sec = 4.0
        n_frames = int(fps * duration_sec)
        t = np.linspace(0, duration_sec, n_frames, endpoint=False)

        # Synthetic heart rate: 72 BPM -> f = 1.2 Hz
        pulse_hz = 1.2
        # Human skin reflection: green channel absorbs oxyhemoglobin pulse (subtle -0.015 modulation)
        base_r = 180.0
        base_g = 130.0
        base_b = 100.0

        r_trace = base_r + 0.5 * np.sin(2 * np.pi * pulse_hz * t)
        g_trace = base_g - 2.0 * np.sin(2 * np.pi * pulse_hz * t)  # Stronger BVP component in Green
        b_trace = base_b + 0.3 * np.sin(2 * np.pi * pulse_hz * t)

        rgb_traces = np.stack([r_trace, g_trace, b_trace], axis=1)

        # Test CHROM
        chrom_sig = compute_chrom_pulse(rgb_traces, fps)
        assert len(chrom_sig) == n_frames
        f_chrom, bpm_chrom, snr_chrom, ent_chrom = compute_psd_snr(chrom_sig, fps)
        assert abs(f_chrom - pulse_hz) < 0.2
        assert abs(bpm_chrom - 72.0) < 10.0
        assert snr_chrom > 0.0

        # Test POS
        pos_sig = compute_pos_pulse(rgb_traces, fps)
        assert len(pos_sig) == n_frames
        f_pos, bpm_pos, snr_pos, ent_pos = compute_psd_snr(pos_sig, fps)
        assert abs(f_pos - pulse_hz) < 0.2
        assert abs(bpm_pos - 72.0) < 10.0

    def test_cross_region_coherence_and_liveness_pipeline(self):
        """Tests full biometric rPPG pipeline on synthetic video sequence."""
        fps = 30.0
        n_frames = 60
        frames = []
        t = np.linspace(0, 2.0, n_frames, endpoint=False)

        for i in range(n_frames):
            # Create synthetic facial frame (120x120 RGB) with synchronized BVP modulation
            pulse_val = float(np.sin(2 * np.pi * 1.2 * t[i]))
            frame = np.zeros((120, 120, 3), dtype=np.uint8)
            # Skin tone: R=190, G=140 - pulse*3, B=110
            frame[:, :, 0] = int(190 + pulse_val)
            frame[:, :, 1] = int(np.clip(140 - pulse_val * 4, 0, 255))
            frame[:, :, 2] = int(110 + pulse_val)
            frames.append(frame)

        rep = analyze_biometrics_rppg(frames, fps=fps)
        assert rep.is_analyzed is True
        assert rep.frame_count == n_frames
        assert rep.fps == fps
        assert rep.chrom_pulse is not None
        assert rep.pos_pulse is not None
        assert rep.dominant_bpm > 40.0
        assert rep.blink_dynamics is not None
        assert rep.corneal_reflection is not None

    def test_corneal_specular_and_blink_dynamics(self):
        """Tests corneal reflection disparity and EAR blink analysis."""
        # Create single frame with symmetric eye glints
        frame = np.full((100, 100, 3), 128, dtype=np.uint8)
        # Left eye: pupil at (33, 33), glint at (34, 34)
        frame[33, 33] = [20, 20, 20]
        frame[34, 34] = [250, 250, 250]
        # Right eye: pupil at (33, 63), glint at (34, 64)
        frame[33, 63] = [20, 20, 20]
        frame[34, 64] = [250, 250, 250]

        refl = evaluate_corneal_specular_reflection(frame)
        assert refl.is_specular_consistent is True
        assert refl.disparity_score < 0.25


# ==============================================================================
# 3. SENSOR DUST & LENS DISTORTION TESTS
# ==============================================================================

class TestOpticsDustModule:
    """Tests for Sensor Dust Invariant Mapping and Brown-Conrady Lens Distortion."""

    def test_sensor_dust_speck_extraction(self):
        """Tests multi-scale LoG extraction of stationary microscopic sensor dust specks."""
        # Create 200x200 uniform background with 3 synthetic dark dust donuts
        img_arr = np.full((200, 200), 200, dtype=np.uint8)

        # Inject dust specks at known coordinates (50, 50), (120, 80), (160, 150)
        speck_coords = [(50, 50), (120, 80), (160, 150)]
        for cx, cy in speck_coords:
            y, x = np.ogrid[-8:9, -8:9]
            r2 = x * x + y * y
            # Gaussian attenuation profile
            atten = 0.15 * np.exp(-r2 / (2.0 * (3.0 ** 2)))
            for dy in range(-8, 9):
                for dx in range(-8, 9):
                    val = float(img_arr[cy + dy, cx + dx]) * (1.0 - atten[dy + 8, dx + 8])
                    img_arr[cy + dy, cx + dx] = int(np.clip(val, 0, 255))

        spots = extract_sensor_dust_spots(img_arr)
        assert len(spots) >= 2
        # Verify detected spot coordinates are within 3 pixels of ground truth
        found_count = 0
        for gx, gy in speck_coords:
            if any(math.hypot(s.x - gx, s.y - gy) <= 3.5 for s in spots):
                found_count += 1
        assert found_count >= 2

    def test_bipartite_dust_matching_camera_ballistics(self):
        """Tests 1:1 camera ballistics bipartite matching between two images from the same camera."""
        # Two reports with shared dust coordinates
        rep_a = SensorDustReport(
            dust_spots_detected=5,
            spots=[
                DustSpot(x=100.0, y=100.0, radius=3.0, optical_depth=0.08, confidence=0.9),
                DustSpot(x=250.0, y=180.0, radius=4.0, optical_depth=0.12, confidence=0.85),
                DustSpot(x=400.0, y=300.0, radius=3.5, optical_depth=0.06, confidence=0.88),
                DustSpot(x=550.0, y=120.0, radius=2.5, optical_depth=0.09, confidence=0.92),
                DustSpot(x=320.0, y=450.0, radius=4.2, optical_depth=0.10, confidence=0.87),
            ]
        )

        # Report B has slight subpixel jitter (< 1.5 px)
        rep_b = SensorDustReport(
            dust_spots_detected=5,
            spots=[
                DustSpot(x=100.8, y=99.5, radius=3.1, optical_depth=0.082, confidence=0.89),
                DustSpot(x=249.4, y=180.6, radius=3.9, optical_depth=0.118, confidence=0.86),
                DustSpot(x=400.5, y=300.2, radius=3.4, optical_depth=0.059, confidence=0.85),
                DustSpot(x=549.7, y=120.4, radius=2.6, optical_depth=0.091, confidence=0.90),
                DustSpot(x=320.3, y=449.6, radius=4.1, optical_depth=0.098, confidence=0.88),
            ]
        )

        match_res = match_sensor_dust(rep_a, rep_b, tolerance_px=4.0)
        assert match_res.is_same_sensor_match is True
        assert match_res.matched_spots_count == 5
        assert match_res.match_score == 1.0
        assert match_res.false_alarm_probability < 1e-4
        assert match_res.verdict == "DEFINITIVE_SAME_SENSOR"

    def test_brown_conrady_distortion_profiling(self):
        """Tests Brown-Conrady radial distortion fitting and synthetic flat image classification."""
        # Flat image should yield zero / synthetic classification
        flat_img = np.full((150, 150), 128, dtype=np.uint8)
        profile = estimate_brown_conrady_distortion(flat_img)
        assert profile.is_synthetic_profile is True
        assert "Synthetic" in profile.distortion_type or "Zero" in profile.distortion_type


# ==============================================================================
# 4. NEURAL STEGANALYSIS & SRM FILTER BANK TESTS
# ==============================================================================

class TestNeuralStegoModule:
    """Tests for Spatial Rich Model (SRM) residuals, Steghide PoV, and OpenPuff scanners."""

    def test_srm_filter_bank_construction_and_submodels(self):
        """Tests SRM 30 directional sub-model filter bank construction."""
        filters = build_srm_filter_bank()
        assert len(filters) >= 12
        assert "1st_horiz" in filters
        assert "2nd_vert" in filters
        assert "3rd_diag" in filters
        assert "edge_3x3" in filters
        assert "square_5x5" in filters

        # Evaluate on clean synthetic image
        img = np.random.RandomState(42).randint(100, 160, size=(120, 120), dtype=np.uint8)
        submodels, score = evaluate_srm_filter_bank(img)
        assert len(submodels) >= 18
        assert 0.0 <= score <= 1.0

    def test_steghide_and_openpuff_scanners(self):
        """Tests Steghide PoV symmetry and OpenPuff multi-bitplane entropy detection."""
        # Create realistic natural gradient image
        gradient = np.tile(np.linspace(40, 220, 100, dtype=np.uint8), (100, 1))
        clean_img = np.stack([gradient, gradient, gradient], axis=2)
        sh_res = scan_steghide_anomaly(clean_img[:, :, 0])
        assert isinstance(sh_res.pov_chi_square, float)

        op_res, bp_entropies = scan_openpuff_and_bitplanes(clean_img)
        assert "R_bit0" in bp_entropies
        assert "G_bit7" in bp_entropies

        # Full neural stego pipeline
        rep = analyze_neural_stego(clean_img)
        assert rep.stego_verdict in ("CLEAN_NATURAL_CARRIER", "S_UNIWARD_ADAPTIVE_STEGO_DETECTED", "CLEAN_CARRIER")
        assert len(rep.srm_submodels) > 0


# ==============================================================================
# 5. NETWORK PCAP PARSER & MEDIA CARVER TESTS
# ==============================================================================

class TestPCAPStreamModule:
    """Tests for PCAP parsing, TCP stream reassembly, and automated multimedia carving."""

    def test_pcap_binary_parsing_and_tcp_reassembly(self):
        """Tests native PCAP container decoding, packet parsing, and TCP stream reassembly."""
        # Build synthetic PCAP file with Global Header + 2 TCP packets
        # PCAP Global Header: magic 0xa1b2c3d4, major 2, minor 4, tz 0, sig 0, snaplen 65535, network 1 (Ethernet)
        global_header = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

        # Packet 1: HTTP GET /image.jpg
        http_req = b"GET /photo.jpg HTTP/1.1\r\nHost: example.com\r\n\r\n"
        # Ethernet (14) + IPv4 (20) + TCP (20) + Payload
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\x08\x00"
        # IPv4: proto 6 (TCP), src 192.168.1.50, dst 93.184.216.34
        ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40 + len(http_req), 0x1234, 0, 64, 6, 0, bytes([192, 168, 1, 50]), bytes([93, 184, 216, 34]))
        # TCP: src port 54321, dst port 80, seq 1000, ack 0, offset 5 (20 bytes), flags PSH|ACK (0x18)
        tcp_hdr = struct.pack(">HHIIHHHH", 54321, 80, 1000, 0, 0x5018, 8192, 0, 0)
        frame1 = eth + ip_hdr + tcp_hdr + http_req

        pkt1_hdr = struct.pack(">IIII", 1700000000, 100000, len(frame1), len(frame1))

        # Packet 2: HTTP 200 OK containing synthetic JPEG image
        # Create a small valid JPEG in bytes
        bio = io.BytesIO()
        Image.new("RGB", (16, 16), color="red").save(bio, format="JPEG")
        jpeg_bytes = bio.getvalue()

        http_resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: image/jpeg\r\n"
            b"Content-Length: " + str(len(jpeg_bytes)).encode() + b"\r\n\r\n" + jpeg_bytes
        )

        ip_hdr2 = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40 + len(http_resp), 0x1235, 0, 64, 6, 0, bytes([93, 184, 216, 34]), bytes([192, 168, 1, 50]))
        tcp_hdr2 = struct.pack(">HHIIHHHH", 80, 54321, 2000, 1000 + len(http_req), 0x5018, 8192, 0, 0)
        frame2 = eth + ip_hdr2 + tcp_hdr2 + http_resp

        pkt2_hdr = struct.pack(">IIII", 1700000000, 200000, len(frame2), len(frame2))

        pcap_raw = global_header + pkt1_hdr + frame1 + pkt2_hdr + frame2

        # Ingest into PCAP Stream Analyzer
        rep = analyze_pcap_stream(pcap_raw)
        assert rep.total_packets == 2
        assert rep.tcp_packets == 2
        assert rep.streams_reconstructed == 1
        assert rep.carved_assets_count >= 1
        assert rep.carved_assets[0].format == "JPEG"
        assert rep.carved_assets[0].is_valid_image is True
        assert rep.carved_assets[0].size_bytes == len(jpeg_bytes)
        assert rep.carved_assets[0].dimensions == (16, 16)
        assert len(rep.carved_assets[0].sha256) == 64

    def test_raw_stream_image_carver(self):
        """Tests carving of PNG and GIF from raw byte streams."""
        # Synthetic stream with embedded PNG
        bio_png = io.BytesIO()
        Image.new("RGB", (8, 8), color="blue").save(bio_png, format="PNG")
        png_bytes = bio_png.getvalue()

        carrier_stream = b"SOMERANDOMPREFIX" + png_bytes + b"SOMERANDOMSUFFIX"
        carved = carve_images_from_raw_stream(
            carrier_stream,
            stream_id=1,
            protocol="RAW_TCP",
            src_ep="10.0.0.1:80",
            dst_ep="10.0.0.2:443",
        )
        assert len(carved) >= 1
        assert carved[0].format == "PNG"
        assert carved[0].is_valid_image is True
        assert carved[0].dimensions == (8, 8)
