"""Unit tests for Wave 10 Precision Hardening & Round 4 Remediations."""
import io
import unittest
from PIL import Image
import numpy as np

from lensint.core.analyzer import ImageAnalyzer
from lensint.core.models import AnalysisResult
from lensint.modules.benchmarks import BayesianForensicFusionEngine
from lensint.modules.stego import detect_overlay_data
from lensint.modules.tampering import analyze_chromatic_aberration, detect_copy_move_dct
from lensint.modules.neural_ai import NeuralDeepfakePipeline
from lensint.modules.c2_stego_decoders import C2StegoDetector


class TestWave10Remediation(unittest.TestCase):
    def test_bayesian_fusion_negative_evidence_dampening(self):
        """Verify that negative tests legitimately reduce log-odds towards clean baseline."""
        # 1. Clean image with all negative tests
        score_clean, verdict_clean, log_clean = BayesianForensicFusionEngine.calculate_calibrated_risk(
            ela_score=10.0,
            copy_move_detected=False,
            dqt_anomaly=False,
            cfa_anomaly=False,
            fft_ai_score=5.0,
            rs_stego_detected=False,
            chi_square_detected=False,
            metadata_anomaly=False,
            malware_threat=False,
            confirmed_payload=False,
            prior_probability=0.10,
        )
        self.assertEqual(verdict_clean, "CLEAN")
        self.assertLess(score_clean, 10.0)

        # 2. Confirmed malicious payload escalates directly to CRITICAL
        score_mal, verdict_mal, log_mal = BayesianForensicFusionEngine.calculate_calibrated_risk(
            ela_score=10.0,
            copy_move_detected=False,
            dqt_anomaly=False,
            cfa_anomaly=False,
            fft_ai_score=5.0,
            rs_stego_detected=False,
            chi_square_detected=False,
            metadata_anomaly=False,
            malware_threat=False,
            confirmed_payload=True,
            prior_probability=0.10,
        )
        self.assertEqual(verdict_mal, "CRITICAL")
        self.assertGreaterEqual(score_mal, 90.0)

    def test_overlay_forward_parsing_with_embedded_image(self):
        """Verify that overlay containing an embedded second image uses true container boundary."""
        # Create a valid PNG
        img = Image.new("RGB", (32, 32), color=(255, 0, 0))
        png_buf = io.BytesIO()
        img.save(png_buf, format="PNG")
        png_bytes = png_buf.getvalue()

        # Create payload that contains a secondary PNG inside it
        payload = b"OVERLAY_HEADER" + png_bytes + b"OVERLAY_TAIL"
        composite = png_bytes + payload

        has_overlay, offset, size, extracted = detect_overlay_data(composite)
        self.assertTrue(has_overlay)
        self.assertEqual(offset, len(png_bytes))
        self.assertEqual(size, len(payload))
        self.assertEqual(extracted, payload)

    def test_achromatic_lens_not_flagged_as_chromatic_aberration(self):
        """Verify that clean image without chromatic fringe does not trigger aberration tampering."""
        # Flat / clean monochromatic or low fringe image
        clean_img = Image.new("RGB", (128, 128), color=(120, 130, 140))
        score, detected = analyze_chromatic_aberration(clean_img)
        self.assertFalse(detected)
        self.assertEqual(score, 0.0)

    def test_monochrome_image_not_flagged_as_deepfake(self):
        """Verify that grayscale / monochrome photo does not receive false RG correlation deepfake penalty."""
        mono_img = Image.new("L", (128, 128), color=128)
        pipe = NeuralDeepfakePipeline()
        res = pipe.predict_synthetic_probability(mono_img)
        self.assertLess(res["heuristic_anomaly_score"], 40.0)

    def test_png_itxt_uncompressed_handling(self):
        """Verify that uncompressed iTXt chunk (comp_flag == 0) is parsed cleanly."""
        # Build PNG with uncompressed iTXt chunk
        # Header + IHDR + iTXt + IEND
        png_header = b"\x89PNG\r\n\x1a\n"
        ihdr_data = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
        ihdr_crc = b"\x90wS\xde"
        ihdr = b"\x00\x00\x00\rIHDR" + ihdr_data + ihdr_crc

        # iTXt: keyword\0 comp_flag(0) comp_method(0) lang\0 trans\0 text
        itxt_body = b"Author\x00\x00\x00en\x00en\x00Forensic Investigator"
        import zlib
        itxt_len = len(itxt_body).to_bytes(4, "big")
        itxt_crc = zlib.crc32(b"iTXt" + itxt_body).to_bytes(4, "big")
        itxt = itxt_len + b"iTXt" + itxt_body + itxt_crc

        iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
        raw_png = png_header + ihdr + itxt + iend

        res = C2StegoDetector.analyze_png_chunks(raw_png)
        self.assertTrue(res["is_png"])
        self.assertTrue(any(m["keyword"] == "Author" for m in res["compressed_metadata"]))


if __name__ == "__main__":
    unittest.main()
