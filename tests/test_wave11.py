"""Unit tests for Wave 11 Deep Forensic Hardening & Round 5 Remediations."""
import io
import os
import shutil
import tempfile
import unittest
from PIL import Image
import numpy as np

from lensint.core.models import AnalysisResult, ThreatIntelReport, StegoReport
from lensint.modules.memory_forensics import _carve_gif_structural
from lensint.modules.stego import detect_overlay_data, perform_chi_square_steganalysis
from lensint.modules.malware_rules import _has_valid_embedded_zip, _has_valid_embedded_pdf, analyze_malware
from lensint.modules.neural_ai import NeuralDeepfakePipeline
from lensint.modules.tampering import analyze_splice_detection
from lensint.reporters.html_rep import export_html_report
from lensint.reporters.misp_rep import export_misp_event
from lensint.reporters.yara_gen import export_yara_rule, generate_yara_rule


class TestWave11Remediation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_gif_structural_carver_import_and_execution(self):
        """Verify _carve_gif_structural is exported and parses valid GIF container."""
        # Create minimal 1x1 GIF
        gif_img = Image.new("P", (8, 8), color=1)
        buf = io.BytesIO()
        gif_img.save(buf, format="GIF")
        gif_bytes = buf.getvalue()

        # Append trailing payload
        payload = b"OVERLAY_CARVED_PAYLOAD_TEST"
        composite = gif_bytes + payload

        carved = _carve_gif_structural(composite, 0)
        self.assertIsNotNone(carved)
        self.assertEqual(carved, gif_bytes)

        # Also test via detect_overlay_data
        has_ov, off, sz, extracted = detect_overlay_data(composite)
        self.assertTrue(has_ov)
        self.assertEqual(off, len(gif_bytes))
        self.assertEqual(sz, len(payload))
        self.assertEqual(extracted, payload)

    def test_threat_intel_live_reputation_field_serialization(self):
        """Verify live_reputation field in ThreatIntelReport is serialized in to_dict."""
        rep = ThreatIntelReport(
            virustotal_file_url="https://virustotal.com/gui/file/test",
            live_reputation={"virustotal": {"positives": 5, "total": 70}},
        )
        d = rep.to_dict()
        self.assertIn("live_reputation", d)
        self.assertEqual(d["live_reputation"]["virustotal"]["positives"], 5)

    def test_single_class_sigmoid_onnx_manifest_default_index(self):
        """Verify single output binary classifier defaults to class_idx=0 without IndexError."""
        pipeline = NeuralDeepfakePipeline()
        manifest = {
            "model_path": "non_existent_dummy.onnx",
            "expected_classes": 1,
            "output_activation": "sigmoid",
        }
        valid, err = pipeline.validate_manifest(manifest)
        self.assertTrue(valid, msg=err)

    def test_polyglot_structural_validation(self):
        """Verify random byte sequence PK\\x03\\x04 is rejected unless valid ZIP EOCD exists."""
        # Random bytes containing only PK\x03\x04 without central directory
        fake_zip_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32 + b"PK\x03\x04" + b"\x00" * 64
        self.assertFalse(_has_valid_embedded_zip(fake_zip_bytes, 16))

        # Real mini zip
        real_zip_bytes = (
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
            + b"PK\x03\x04\x14\x00\x00\x00\x00\x00" + b"\x00" * 20
            + b"PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        self.assertTrue(_has_valid_embedded_zip(real_zip_bytes, 16))

    def test_reporters_auto_create_nested_directories(self):
        """Verify report exporters automatically create non-existent parent directories."""
        res = AnalysisResult(target_path="dummy.png")
        res.integrity.file_name = "dummy.png"
        res.integrity.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        nested_html = os.path.join(self.tmp_dir, "nested", "reports", "report.html")
        export_html_report(res, nested_html)
        self.assertTrue(os.path.exists(nested_html))

        nested_misp = os.path.join(self.tmp_dir, "deep", "misp", "event.json")
        export_misp_event(res, nested_misp)
        self.assertTrue(os.path.exists(nested_misp))

        nested_yara = os.path.join(self.tmp_dir, "yara", "rules", "rule.yar")
        export_yara_rule(res, nested_yara)
        self.assertTrue(os.path.exists(nested_yara))

    def test_yara_gen_tiff_big_and_little_endian(self):
        """Verify YARA rule includes both LE and BE TIFF magic headers."""
        res = AnalysisResult(target_path="test.tiff")
        res.integrity.file_name = "test.tiff"
        res.integrity.detected_format = "TIFF"
        res.integrity.sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        rule_text = generate_yara_rule(res)
        self.assertIn("$magic = { 49 49 2A 00 }", rule_text)
        self.assertIn("$magic_be = { 4D 4D 00 2A }", rule_text)
        self.assertIn("($magic at 0 or $magic_be at 0)", rule_text)


if __name__ == "__main__":
    unittest.main()
