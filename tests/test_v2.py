import io
import json
import os
import tempfile
import unittest
from PIL import Image

from lensint.core.analyzer import ImageAnalyzer
from lensint.core.models import AnalysisResult
from lensint.modules.ai_detect import analyze_ai_generation, calculate_fft_spectrum
from lensint.modules.malware_rules import analyze_malware_and_polyglots
from lensint.modules.tampering import (
    analyze_tampering,
    analyze_jpeg_ghosts,
    analyze_dqt_tables,
    analyze_cfa_demosaicing,
    analyze_block_grid_inconsistency,
    analyze_chromatic_aberration,
    analyze_median_filtering,
    analyze_illumination_consistency,
)
from lensint.modules.threat_intel import generate_threat_intel_links
from lensint.reporters.html_rep import render_html_report
from lensint.reporters.json_rep import render_json_report


class TestLensintV2Forensics(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def create_sample_png(self, w=128, h=128, color=(100, 150, 200)):
        img = Image.new("RGB", (w, h), color=color)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    def create_sample_jpeg(self, w=128, h=128, quality=90):
        img = Image.new("RGB", (w, h), color=(120, 80, 180))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality)
        return buf.getvalue()

    def test_01_integrity_and_hashes(self):
        png_bytes = self.create_sample_png()
        p = os.path.join(self.tmp_dir, "test.png")
        with open(p, "wb") as f:
            f.write(png_bytes)

        res = ImageAnalyzer(p).analyze()
        self.assertEqual(res.integrity.detected_format, "PNG")
        self.assertFalse(res.integrity.extension_mismatch)
        self.assertTrue(len(res.integrity.sha256) == 64)
        self.assertEqual(res.overall_risk_level, "CLEAN")

    def test_02_ai_generation_and_fft_spectrum(self):
        img = Image.new("RGB", (256, 256), color=(200, 200, 200))
        vis, score, peak, suspected = calculate_fft_spectrum(img)
        self.assertIsInstance(score, float)
        self.assertIsInstance(peak, float)
        self.assertFalse(suspected)

        prompt_marker = b"para" + b"meters: cyber" + b"punk cat\nNegative prompt: blur\nSteps: 30, Sampler: Euler, CFG scale: 7"
        ai_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00" + prompt_marker + b"\xFF\xD9"
        ai_rep = analyze_ai_generation(ai_bytes, None)
        self.assertTrue(ai_rep.ai_generator_detected)
        self.assertEqual(ai_rep.ai_verdict, "CONFIRMED_AI")
        self.assertEqual(ai_rep.ai_probability_score, 100.0)

    def test_03_malware_and_polyglot_detection(self):
        php_tag = b"<" + b"?" + b"ph" + b"p"
        exec_tag = b"sys" + b"tem("
        gifar_payload = b"GIF89a" + b"\x00" * 30 + php_tag + b" " + exec_tag + b"$_GET['c']);"
        mal_rep1 = analyze_malware_and_polyglots(gifar_payload)
        self.assertTrue(mal_rep1.is_polyglot)
        self.assertTrue(mal_rep1.webshell_detected)
        self.assertEqual(mal_rep1.severity, "CRITICAL")

        eval_tag = b"ev" + b"al(" + b"base" + b"64_decode("
        webshell_bytes = b"\x89PNG\r\n\x1a\n" + eval_tag + b"'...')" + b"IEND\xaeB`\x82"
        mal_rep2 = analyze_malware_and_polyglots(webshell_bytes)
        self.assertTrue(mal_rep2.webshell_detected)
        self.assertTrue(mal_rep2.has_threats)

    def test_04_deep_courtroom_tampering_forensics(self):
        img = Image.new("RGB", (256, 256), color=(255, 255, 255))
        from PIL import ImageDraw
        draw = ImageDraw.Draw(img)
        for offset in [20, 150]:
            draw.rectangle([offset, 20, offset + 40, 60], fill=(20, 20, 20))
            draw.line([offset, 20, offset + 40, 60], fill=(255, 0, 0), width=3)

        # 1. Full tampering master orchestrator
        tamp_rep = analyze_tampering(img)
        self.assertTrue(tamp_rep.ela_performed)
        self.assertIsInstance(tamp_rep.ela_suspicion_score, float)
        self.assertIsNotNone(tamp_rep.ela_b64_image)

        # 2. JPEG Ghost Analysis
        ghost_det, ghost_quals, ghost_score, ghost_vis = analyze_jpeg_ghosts(img)
        self.assertIsInstance(ghost_det, bool)
        self.assertIsInstance(ghost_score, float)

        # 3. DQT Extraction
        jpg_bytes = self.create_sample_jpeg()
        dqt_found, dqt_enc, dqt_q, dqt_mismatch, dqt_tabs = analyze_dqt_tables(jpg_bytes)
        self.assertTrue(dqt_found)
        self.assertIn("Luminance", dqt_tabs)
        self.assertIsInstance(dqt_q, int)

        # 4. CFA Demosaicing
        cfa_score, cfa_det = analyze_cfa_demosaicing(img)
        self.assertIsInstance(cfa_score, float)
        self.assertIsInstance(cfa_det, bool)

        # 5. 8x8 DCT Block Grid
        grid_shift, grid_offset, bag_score = analyze_block_grid_inconsistency(img)
        self.assertIsInstance(grid_shift, bool)
        self.assertEqual(len(grid_offset), 2)

        # 6. Chromatic Aberration
        ca_score, ca_det = analyze_chromatic_aberration(img)
        self.assertIsInstance(ca_score, float)

        # 7. Median Filtering
        mf_det, mf_score = analyze_median_filtering(img)
        self.assertIsInstance(mf_det, bool)

        # 8. Illumination Consistency
        illum_score, illum_det = analyze_illumination_consistency(img)
        self.assertIsInstance(illum_score, float)

    def test_05_stego_overlay_extraction(self):
        jpeg_bytes = self.create_sample_jpeg()
        hidden_payload = b"SAMPLE_PAYLOAD_TEST_BYTES_2026"
        carrier = jpeg_bytes + hidden_payload

        p = os.path.join(self.tmp_dir, "stego_carrier.jpg")
        with open(p, "wb") as f:
            f.write(carrier)

        res = ImageAnalyzer(p).analyze()
        self.assertTrue(res.stego.has_overlay_data)
        self.assertEqual(res.stego.overlay_size_bytes, len(hidden_payload))

    def test_06_threat_intel_generation(self):
        intel_rep = generate_threat_intel_links(
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ips=["192.168.1.100", "8.8.8.8"],
            domains=["example-domain.com"],
            urls=["http://example-domain.com/test"],
        )
        self.assertIn("virustotal.com", intel_rep.virustotal_file_url)
        self.assertIn("192.168.1.100", intel_rep.ip_lookups)
        self.assertIn("Google Lens", intel_rep.reverse_image_engines)

    def test_07_reports_html_and_json(self):
        p = os.path.join(self.tmp_dir, "sample.png")
        with open(p, "wb") as f:
            f.write(self.create_sample_png())

        res = ImageAnalyzer(p).analyze()
        json_out = render_json_report(res)
        parsed = json.loads(json_out)
        self.assertEqual(parsed["integrity"]["detected_format"], "PNG")
        self.assertIn("tampering", parsed)
        self.assertIn("jpeg_ghosts_detected", parsed["tampering"])
        self.assertIn("dqt_identified_encoder", parsed["tampering"])
        self.assertIn("cfa_inconsistency_score", parsed["tampering"])

        html_out = render_html_report(res)
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("LENSINT", html_out)
        self.assertIn("Courtroom-Grade Tampering", html_out)

    def test_08_screenshot_contextualization(self):
        # 1920x1080 standard desktop screenshot simulation
        img = Image.new("RGB", (1920, 1080), color=(240, 240, 240))
        p = os.path.join(self.tmp_dir, "screenshot_test.png")
        img.save(p, format="PNG")

        res = ImageAnalyzer(p).analyze()
        self.assertTrue(res.integrity.is_screenshot)
        self.assertEqual(res.overall_risk_level, "CLEAN")
        self.assertEqual(res.overall_risk_score, 0.0)


if __name__ == "__main__":
    unittest.main()
