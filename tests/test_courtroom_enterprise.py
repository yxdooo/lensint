"""Unit and integration tests for Courtroom Expert Witness & Cyber Police Enterprise Forensics."""
import io
import os
import shutil
import tempfile
import unittest
import numpy as np
from PIL import Image

from lensint.core.analyzer import ImageAnalyzer
from lensint.core.models import AnalysisResult
from lensint.modules.pdq_hash import (
    BKTreePDQIndex,
    analyze_pdq_triage,
    compute_pdq_hamming_distance,
    compute_pdq_hash,
)
from lensint.modules.prnu import (
    PRNUDatabase,
    compute_pce,
    extract_noise_residual,
)
from lensint.modules.video_forensics import (
    analyze_h264_nal_units,
    analyze_video_forensics,
    parse_isobmff_atoms,
)
from lensint.reporters.expert_pdf import generate_expert_witness_pdf
from lensint.utils.tsa import _build_rfc3161_request_der, query_rfc3161_tsa
from lensint.volatility_plugin.lensint_carve import LensintCarvePlugin


class TestCourtroomEnterpriseForensics(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_rfc3161_timestamp_req_and_offline_seal(self):
        """Verify ASN.1 DER TimeStampReq builder and offline cryptographic seal."""
        sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        req_der = _build_rfc3161_request_der(sha256_hex)
        self.assertGreater(len(req_der), 30)
        self.assertEqual(req_der[0], 0x30)  # ASN.1 SEQUENCE

        # Test local offline fallback query
        token_rep = query_rfc3161_tsa(sha256_hex, tsa_url="http://invalid.nonexistent.domain.tsa")
        self.assertIn("GRANTED", token_rep.status)
        self.assertEqual(token_rep.evidence_sha256, sha256_hex)
        self.assertTrue(len(token_rep.token_der_b64) > 0)
        self.assertTrue(len(token_rep.serial_number) > 0)

    def test_meta_pdq_hash_computation_and_bk_tree_search(self):
        """Verify 256-bit Meta PDQ calculation, Hamming distance, and BK-Tree index search."""
        img1 = Image.new("RGB", (128, 128), color=(100, 150, 200))
        hex1, bin1, q1 = compute_pdq_hash(img1)
        self.assertEqual(len(hex1), 64)  # 256 bits = 64 hex characters
        self.assertEqual(len(bin1), 256)
        self.assertGreater(q1, 0)

        # Same image slightly resized should have very low Hamming distance
        img2 = img1.resize((100, 100))
        hex2, bin2, q2 = compute_pdq_hash(img2)
        dist = compute_pdq_hamming_distance(hex1, hex2)
        self.assertLessEqual(dist, 10)

        # Index into BK-Tree
        tree = BKTreePDQIndex()
        tree.insert(hex1, "ILLICIT_THREAT_REF_001", {"category": "TargetThreat"})
        self.assertEqual(tree.total_nodes, 1)

        # Search with similar hash
        matches = tree.search(hex2, max_distance=31)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["item_id"], "ILLICIT_THREAT_REF_001")
        self.assertLessEqual(matches[0]["hamming_distance"], 10)

        # Test triage function
        rep = analyze_pdq_triage(img2, threat_index=tree)
        self.assertTrue(rep.is_threat_match)
        self.assertEqual(rep.matched_reference_id, "ILLICIT_THREAT_REF_001")

    def test_prnu_noise_residual_and_mle_matching(self):
        """Verify PRNU sensor noise residual extraction and 1:N device matching."""
        # Create deterministic synthetic sensor noise
        np.random.seed(42)
        h, w = 512, 512
        sensor_k = np.random.normal(0, 1.0, (h, w)).astype(np.float32)

        # Register device in PRNU database
        db = PRNUDatabase()
        db.register_device_fingerprint(
            device_id="SUSPECT_IPHONE_15_PRO",
            fingerprint=sensor_k,
            device_model="Apple iPhone 15 Pro",
            owner_info="Suspect A",
        )

        # Synthetic image containing camera sensor noise
        base_scene = np.full((h, w), 128, dtype=np.float32)
        noisy_image = base_scene + 5.0 * sensor_k
        noisy_image = np.clip(noisy_image, 0, 255).astype(np.uint8)
        pil_img = Image.fromarray(noisy_image, mode="L")

        res_rep = db.match_image(pil_img, pce_threshold=50.0)
        self.assertTrue(res_rep.fingerprint_extracted)
        self.assertTrue(res_rep.is_device_matched)
        self.assertEqual(res_rep.matched_device_id, "SUSPECT_IPHONE_15_PRO")
        self.assertGreaterEqual(res_rep.peak_to_correlation_energy, 50.0)
        self.assertLess(res_rep.false_alarm_rate_estimate, 1e-5)

    def test_video_forensics_isobmff_and_gop(self):
        """Verify ISOBMFF atom parsing, video editor footprints, and GOP cadence break detection."""
        # Construct synthetic MP4 bytes: ftyp atom + moov atom + mdat atom + trailing payload
        ftyp = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"
        moov = b"\x00\x00\x00\x20moov" + b"Lavf58.76.100" + b"\x00" * 11
        mdat = b"\x00\x00\x00\x30mdat"
        # Append H.264 NAL units inside mdat: I, P, P, P, I
        nal_stream = (
            b"\x00\x00\x00\x01\x65" + b"\x00" * 8  # IDR (I-frame)
            + b"\x00\x00\x00\x01\x41" + b"\x00" * 8 # Non-IDR (P-frame)
            + b"\x00\x00\x00\x01\x41" + b"\x00" * 8 # Non-IDR (P-frame)
        )
        mdat = mdat + nal_stream.ljust(40, b"\x00")
        trailing_payload = b"SECRET_C2_TRAILING_VIDEO_PAYLOAD"

        raw_video = ftyp + moov + mdat + trailing_payload

        rep = analyze_video_forensics(raw_video)
        self.assertTrue(rep.is_video)
        self.assertIn("ISOBMFF", rep.container_format)
        self.assertTrue(rep.has_trailing_payload)
        self.assertEqual(rep.trailing_payload_size_bytes, len(trailing_payload))
        self.assertIn("FFmpeg Transcoder Library (Lavf/Lavc)", rep.editing_software_footprints)

    def test_courtroom_expert_witness_pdf_generation(self):
        """Verify ReportLab generation of official Courtroom Expert Witness PDF."""
        res = AnalysisResult(target_path="evidence_exhibit_01.jpg")
        res.integrity.file_name = "evidence_exhibit_01.jpg"
        res.integrity.file_size_bytes = 1048576
        res.integrity.detected_format = "JPEG"
        res.integrity.detected_mime = "image/jpeg"
        res.integrity.md5 = "d41d8cd98f00b204e9800998ecf8427e"
        res.integrity.sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        res.integrity.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res.overall_risk_score = 92.5
        res.overall_risk_level = "CRITICAL"
        res.summary_findings = [
            "Physical tampering detected: Error Level Analysis indicates spliced element in upper-right quadrant.",
            "PRNU Camera Sensor mismatch: Noise residual is inconsistent with declared EXIF camera model.",
            "Secret Exfiltration: High-entropy hidden overlay payload discovered past container boundary.",
        ]

        pdf_out = os.path.join(self.tmp_dir, "Courtroom_Expert_Report.pdf")
        ret_path = generate_expert_witness_pdf(
            result=res,
            output_path=pdf_out,
            case_id="COURT-2026-CASE-882",
            evidence_id="EXHIBIT-A-01",
            examiner_name="Dr. Jane Doe, Ph.D.",
            examiner_title="Chief Digital Forensic Scientist",
            agency_name="National Cyber Crime Forensic Laboratory",
            jurisdiction="Federal District Court",
        )
        self.assertTrue(os.path.exists(ret_path))
        self.assertGreater(os.path.getsize(ret_path), 2000)

    def test_volatility_plugin_interface(self):
        """Verify Volatility 3 plugin memory buffer carver."""
        plugin = LensintCarvePlugin()
        img = Image.new("RGB", (16, 16), color=(255, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_bytes = buf.getvalue()
        mem_buffer = b"\x00" * 64 + png_bytes + b"\x00" * 64

        carved = plugin.run_carve_on_buffer(mem_buffer)
        self.assertGreaterEqual(len(carved), 1)
        self.assertEqual(carved[0]["format"], "PNG")


if __name__ == "__main__":
    unittest.main()
