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

    def test_09_stix_threat_bundle_export(self):
        from lensint.reporters.stix_rep import export_stix_report, render_stix_report

        p = os.path.join(self.tmp_dir, "sample.png")
        with open(p, "wb") as f:
            f.write(self.create_sample_png())

        res = ImageAnalyzer(p, use_cache=False).analyze()
        stix_json = render_stix_report(res)
        parsed = json.loads(stix_json)

        self.assertEqual(parsed["type"], "bundle")
        self.assertIn("objects", parsed)
        types = [obj["type"] for obj in parsed["objects"]]
        self.assertIn("file", types)

        out_path = os.path.join(self.tmp_dir, "threat.stix.json")
        saved = export_stix_report(res, out_path)
        self.assertTrue(os.path.exists(saved))

    def test_10_caching_performance(self):
        p = os.path.join(self.tmp_dir, "sample.png")
        with open(p, "wb") as f:
            f.write(self.create_sample_png())

        # First run (cache miss or populated)
        res1 = ImageAnalyzer(p, use_cache=True).analyze()
        # Second run (cache hit)
        res2 = ImageAnalyzer(p, use_cache=True).analyze()
        self.assertTrue(res2.cache_hit)
        self.assertEqual(res1.integrity.sha256, res2.integrity.sha256)
        self.assertEqual(res1.overall_risk_level, res2.overall_risk_level)

    def test_11_splice_and_multiscale_ela(self):
        # Create JPEG for ELA and Splice testing
        img = Image.new("RGB", (300, 300), color=(100, 150, 200))
        p = os.path.join(self.tmp_dir, "test_ela.jpg")
        img.save(p, format="JPEG", quality=85)

        res = ImageAnalyzer(p, use_cache=False).analyze()
        self.assertTrue(res.tampering.ela_performed)
        self.assertGreaterEqual(res.tampering.ela_confidence, 0.0)
        self.assertIsNotNone(res.tampering.splice_detected)

    def test_12_high_entropy_section_detection(self):
        from lensint.modules.malware_rules import analyze_malware_and_polyglots

        # High entropy random payload simulation
        random_bytes = b"\x89PNG\r\n\x1a\n" + os.urandom(2048)
        report = analyze_malware_and_polyglots(random_bytes)
        self.assertTrue(report.packed_payload_detected)
        self.assertGreater(len(report.high_entropy_sections), 0)

    def test_13_rs_steganalysis_and_tool_signatures(self):
        from lensint.modules.stego import analyze_stego

        # Stego tool signature presence simulation
        raw_stego = b"\x89PNG\r\n\x1a\n" + b"OPENSTEGO_PAYLOAD_HERE" + b"IEND\xaeB`\x82"
        img = Image.new("RGB", (64, 64), color=(50, 100, 150))
        report = analyze_stego(raw_stego, img)
        self.assertGreater(len(report.stego_tool_signatures), 0)
        self.assertIn("OpenStego", report.stego_tool_signatures[0])

    def test_14_yara_and_auto_deobfuscator(self):
        from lensint.modules.malware_rules import analyze_malware_and_polyglots

        # 1-Byte XOR encrypted string simulation (Key: 0x5A)
        # target: "http://malicious-c2.com/beacon"
        target = b"http://malicious-c2.com/beacon"
        xor_bytes = bytes([b ^ 0x5A for b in target])
        simulated_img_data = b"\xFF\xD8\xFF" + (b"\x00" * 100) + xor_bytes + (b"\x00" * 100)

        report = analyze_malware_and_polyglots(simulated_img_data)
        self.assertGreater(len(report.deobfuscated_payloads), 0)
        self.assertEqual(report.deobfuscated_payloads[0]["matched_target"], "http://")

    def test_15_prnu_and_inpainting_detection(self):
        from lensint.modules.ai_detect import analyze_prnu_sensor_noise, detect_inpainting_anomalies

        img = Image.new("RGB", (128, 128), color=(120, 120, 120))
        present, score = analyze_prnu_sensor_noise(img)
        self.assertIsInstance(present, bool)
        self.assertGreaterEqual(score, 0.0)

        inpaint_score = detect_inpainting_anomalies(img)
        self.assertGreaterEqual(inpaint_score, 0.0)

    def test_16_thumbnail_mismatch_and_provenance(self):
        from lensint.modules.metadata import _detect_social_media_provenance

        # WhatsApp signature simulation (1600px, no Exif)
        img = Image.new("RGB", (1600, 1200), color=(10, 20, 30))
        raw_jpeg = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        prov = _detect_social_media_provenance(raw_jpeg, img, has_exif=False)
        self.assertIsNotNone(prov)
        self.assertIn("WhatsApp", prov)


if __name__ == "__main__":
    unittest.main()


