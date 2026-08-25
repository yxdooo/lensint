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
    analyze_video_nal_units,
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
        """Verify 256-bit Meta PDQ calculation, sensitivity to entire image field, and BK-Tree search."""
        # Non-uniform image
        arr = np.zeros((128, 128, 3), dtype=np.uint8)
        arr[:64, :64] = [255, 0, 0]      # Top-left red
        arr[:64, 64:] = [0, 255, 0]      # Top-right green
        arr[64:, :64] = [0, 0, 255]      # Bottom-left blue
        arr[64:, 64:] = [255, 255, 0]    # Bottom-right yellow
        img1 = Image.fromarray(arr)

        hex1, bin1, q1 = compute_pdq_hash(img1)
        self.assertEqual(len(hex1), 64)  # 256 bits = 64 hex characters
        self.assertEqual(len(bin1), 256)
        self.assertGreater(q1, 0)

        # Modifying only the bottom-right quadrant must alter the PDQ hash (verifying full 64x64 DCT projection)
        arr_mod = arr.copy()
        arr_mod[64:, 64:] = [0, 0, 0]    # Change bottom-right to black
        img_mod = Image.fromarray(arr_mod)
        hex_mod, _, _ = compute_pdq_hash(img_mod)
        self.assertNotEqual(hex1, hex_mod)
        dist_mod = compute_pdq_hamming_distance(hex1, hex_mod)
        self.assertGreater(dist_mod, 0)

        # Resized version should maintain low Hamming distance (within standard PDQ match threshold 31)
        img2 = img1.resize((100, 100))
        hex2, bin2, q2 = compute_pdq_hash(img2)
        dist = compute_pdq_hamming_distance(hex1, hex2)
        self.assertLessEqual(dist, 31)

        # Index into BK-Tree with duplicate collision handling
        tree = BKTreePDQIndex()
        tree.insert(hex1, "ILLICIT_THREAT_REF_001", {"category": "TargetThreat"})
        tree.insert(hex1, "ILLICIT_THREAT_REF_002", {"category": "DuplicateThreat"})
        self.assertEqual(tree.total_nodes, 1)

        # Search with similar hash
        matches = tree.search(hex2, max_distance=31)
        self.assertEqual(len(matches), 2)
        item_ids = [m["item_id"] for m in matches]
        self.assertIn("ILLICIT_THREAT_REF_001", item_ids)
        self.assertIn("ILLICIT_THREAT_REF_002", item_ids)

        # Test triage function
        rep = analyze_pdq_triage(img2, threat_index=tree)
        self.assertTrue(rep.is_threat_match)

    def test_prnu_noise_residual_and_mle_matching(self):
        """Verify PRNU sensor noise residual extraction, MLE reference synthesis, and 1:N device matching."""
        np.random.seed(42)
        h, w = 512, 512
        sensor_k = np.random.normal(0, 1.0, (h, w)).astype(np.float32)

        # Create multiple calibration photos for MLE synthesis
        calibration_images = []
        for i in range(4):
            base_scene = np.full((h, w), 100 + i * 20, dtype=np.float32)
            cal_img_arr = np.clip(base_scene + 6.0 * sensor_k, 0, 255).astype(np.uint8)
            calibration_images.append(Image.fromarray(cal_img_arr, mode="L"))

        db = PRNUDatabase()
        db.create_reference_from_images(
            device_id="SUSPECT_IPHONE_15_PRO",
            image_list=calibration_images,
            device_model="Apple iPhone 15 Pro",
        )

        # Unknown test evidence photo taken by the same suspect sensor
        test_scene = np.full((h, w), 140, dtype=np.float32)
        noisy_image = np.clip(test_scene + 6.0 * sensor_k, 0, 255).astype(np.uint8)
        pil_img = Image.fromarray(noisy_image, mode="L")

        res_rep = db.match_image(pil_img, pce_threshold=40.0)
        self.assertTrue(res_rep.fingerprint_extracted)
        self.assertTrue(res_rep.is_device_matched)
        self.assertEqual(res_rep.matched_device_id, "SUSPECT_IPHONE_15_PRO")
        self.assertGreaterEqual(res_rep.peak_to_correlation_energy, 40.0)
        self.assertLess(res_rep.false_alarm_rate_estimate, 1e-4)

    def test_video_forensics_isobmff_and_gop(self):
        """Verify ISOBMFF atom parsing, AVCC NAL units, and video editor footprints."""
        ftyp = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"
        moov = b"\x00\x00\x00\x20moov" + b"Lavf58.76.100" + b"\x00" * 11
        mdat = b"\x00\x00\x00\x30mdat"
        # Append AVCC length-prefixed NAL units inside mdat
        nal_stream = (
            b"\x00\x00\x00\x05\x65\x00\x00\x00\x00"  # IDR (I-frame)
            + b"\x00\x00\x00\x05\x41\x00\x00\x00\x00" # Non-IDR (P-frame)
            + b"\x00\x00\x00\x05\x41\x00\x00\x00\x00" # Non-IDR (P-frame)
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
        self.assertGreaterEqual(rep.total_frames_analyzed, 1)

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
        res.integrity.sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
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

    def test_analyzer_courtroom_modules_and_cache(self):
        """Verify ImageAnalyzer populates PRNU, PDQ, and TSA, and restores them from cache."""
        test_img_path = os.path.join(self.tmp_dir, "test_evidence.png")
        img = Image.new("RGB", (64, 64), color=(120, 140, 160))
        img.save(test_img_path)

        analyzer = ImageAnalyzer(test_img_path, use_cache=True)
        res1 = analyzer.analyze()
        self.assertTrue(res1.prnu.fingerprint_extracted)
        self.assertTrue(len(res1.pdq.pdq_hash_hex) > 0)
        self.assertTrue(len(res1.timestamp_token.status) > 0)

        # Second run should hit cache and restore PRNU and PDQ
        analyzer2 = ImageAnalyzer(test_img_path, use_cache=True)
        res2 = analyzer2.analyze()
        self.assertTrue(res2.cache_hit)
        self.assertTrue(res2.prnu.fingerprint_extracted)
        self.assertEqual(res1.pdq.pdq_hash_hex, res2.pdq.pdq_hash_hex)


if __name__ == "__main__":
    unittest.main()
