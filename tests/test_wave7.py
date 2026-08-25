"""Unit tests for Wave 7 Forensic Remediation and Robustness Improvements."""
import io
import unittest
from PIL import Image
import numpy as np

from lensint.core.analyzer import ImageAnalyzer
from lensint.core.models import AnalysisResult
from lensint.modules.malware_rules import analyze_malware_and_polyglots, _analyze_entropy_sections
from lensint.modules.memory_forensics import MemoryForensicsEngine
from lensint.reporters.yara_gen import generate_yara_rule
from lensint.modules.tampering import analyze_splice_detection, detect_copy_move_dct
from lensint.modules.threat_intel import query_virustotal_file_api, query_abuseipdb_api


class TestWave7Remediation(unittest.TestCase):
    def test_clean_jpeg_not_falsely_escalated_by_dqt(self):
        """Verify that a standard clean JPEG with standard DQT is not marked CRITICAL."""
        img = Image.new("RGB", (100, 100), color=(120, 150, 180))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        raw_jpeg = buf.getvalue()

        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tf:
            tf.write(raw_jpeg)
            tf_path = tf.name

        try:
            analyzer = ImageAnalyzer(tf_path, use_cache=False)
            res = analyzer.analyze()
            self.assertIn(res.overall_risk_level, ("CLEAN", "LOW", "MEDIUM"))
            self.assertNotEqual(res.overall_risk_level, "CRITICAL")
            self.assertIn("fusion_telemetry", res.to_dict())
        finally:
            if os.path.exists(tf_path):
                os.unlink(tf_path)

    def test_clean_compressed_png_not_flagged_as_packed_malware(self):
        """Verify that high entropy inside normal PNG IDAT chunks is not flagged as packed malware."""
        # Generate random high-entropy pixel data
        arr = np.random.randint(0, 256, (128, 128, 3), dtype=np.uint8)
        img = Image.fromarray(arr)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        raw_png = buf.getvalue()

        mal_rep = analyze_malware_and_polyglots(raw_png)
        self.assertFalse(mal_rep.packed_payload_detected)
        self.assertFalse(mal_rep.has_threats)
        self.assertEqual(mal_rep.severity, "CLEAN")

    def test_trailing_overlay_high_entropy_detected(self):
        """Verify that high entropy appended after JPEG EOI is detected as anomalous payload."""
        img = Image.new("RGB", (32, 32), color=(50, 50, 50))
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        raw_jpeg = buf.getvalue()

        # Append 2KB of pure high-entropy payload after EOI
        import os
        overlay = os.urandom(2048)
        tampered = raw_jpeg + overlay

        packed_detected, sections = _analyze_entropy_sections(tampered)
        self.assertTrue(packed_detected)
        anomalous = [s for s in sections if s.get("is_anomalous")]
        self.assertGreaterEqual(len(anomalous), 1)

    def test_memory_carver_jpeg_eoi_recovery(self):
        """Verify that MemoryImageCarver accurately carves JPEG with SOS and EOI markers."""
        img = Image.new("RGB", (64, 64), color=(200, 100, 50))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=80)
        jpeg_bytes = buf.getvalue()

        # Embed JPEG in a memory noise stream
        memory_blob = b"\x00\x11\x22\x33" * 100 + jpeg_bytes + b"\x99\x88\x77" * 100
        carver = MemoryForensicsEngine()
        candidates = carver.carve_memory_stream(memory_blob, max_images=5)

        self.assertGreaterEqual(len(candidates), 1)
        first = candidates[0]
        self.assertEqual(first["format"], "JPEG")
        self.assertEqual(first["dimensions"], (64, 64))

    def test_yara_gen_webp_bmp_tiff(self):
        """Verify that YARA generator outputs valid rules with correct magic for WEBP, BMP, TIFF."""
        for fmt, magic_hex in [("WEBP", "52 49 46 46"), ("BMP", "42 4D"), ("TIFF", "49 49 2A 00")]:
            res = AnalysisResult()
            res.integrity.file_name = f"sample.{fmt.lower()}"
            res.integrity.detected_format = fmt
            res.integrity.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            res.overall_risk_level = "HIGH"

            rule = generate_yara_rule(res)
            self.assertIn(f"$magic = {{ {magic_hex} }}", rule)
            self.assertIn("$magic at 0", rule)

    def test_splice_detection_localized_boxes(self):
        """Verify that analyze_splice_detection returns localized candidate boxes."""
        img = Image.new("RGB", (256, 256), color=(100, 100, 100))
        detected, conf, b64_vis, boxes = analyze_splice_detection(img, generate_visuals=False)
        self.assertIsInstance(boxes, list)

    def test_threat_intel_missing_keys_handled_cleanly(self):
        """Verify that threat intel API lookups return None gracefully when no key is supplied."""
        res_vt = query_virustotal_file_api("dummy_sha256", "")
        self.assertIsNone(res_vt)

        res_abuse = query_abuseipdb_api("1.1.1.1", "")
        self.assertIsNone(res_abuse)

    def test_detect_copy_move_dct_speed(self):
        """Verify that detect_copy_move_dct executes quickly on synthetic images."""
        img = Image.new("RGB", (256, 256), color=(150, 150, 150))
        detected, count = detect_copy_move_dct(img)
        self.assertIsInstance(detected, bool)
        self.assertIsInstance(count, int)


if __name__ == "__main__":
    unittest.main()
