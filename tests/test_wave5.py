import io
import json
import os
import shutil
import tempfile
import unittest
import numpy as np
from PIL import Image

from lensint.modules.jpeg_dct import (
    parse_jpeg_dct_coefficients,
    get_nonzero_ac_coefficients,
    estimate_jsteg_payload,
    analyze_f5_capacity,
    analyze_outguess_stats,
)
from lensint.modules.c2_stego_decoders import C2StegoDetector
from lensint.modules.stego import perform_rs_steganalysis
from lensint.modules.edr_sandbox import SandboxIngestionEngine
from lensint.modules.tampering import analyze_chromatic_aberration
from lensint.modules.ai_detect import analyze_noise_floor_consistency, analyze_ai_generation


class TestWave5RealityUpgrades(unittest.TestCase):
    def setUp(self):
        # Create a standard baseline JPEG with rich gradient/pattern
        x = np.linspace(0, 255, 64, dtype=np.uint8)
        y = np.linspace(0, 255, 64, dtype=np.uint8)
        xx, yy = np.meshgrid(x, y)
        arr = np.stack([xx, yy, (xx // 2 + yy // 2)], axis=-1).astype(np.uint8)
        img = Image.fromarray(arr)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        self.jpeg_bytes = buf.getvalue()

    def test_jpeg_dct_extractor_and_analysis(self):
        # 1. Test extraction of 8x8 DCT blocks from baseline JPEG
        blocks = parse_jpeg_dct_coefficients(self.jpeg_bytes)
        self.assertIsInstance(blocks, list)
        self.assertGreater(len(blocks), 0)
        # Each block must have exactly 64 DCT coefficients
        self.assertEqual(len(blocks[0]), 64)

        # 2. Test non-zero AC coefficients
        nonzero_ac = get_nonzero_ac_coefficients(self.jpeg_bytes)
        self.assertIsInstance(nonzero_ac, list)

        # 3. Test JSteg payload estimator
        jsteg_res = estimate_jsteg_payload(self.jpeg_bytes)
        self.assertIn("carrier_coefficients", jsteg_res)
        self.assertIn("capacity_bytes", jsteg_res)
        self.assertIn("status", jsteg_res)

        # 4. Test F5 capacity analysis
        f5_res = analyze_f5_capacity(self.jpeg_bytes)
        self.assertIn("net_capacity_bytes", f5_res)
        self.assertIn("lsb_anomaly_score", f5_res)

        # 5. Test OutGuess histogram symmetry
        outguess_res = analyze_outguess_stats(self.jpeg_bytes)
        self.assertIn("histogram_symmetry_score", outguess_res)
        self.assertIn("outguess_score", outguess_res)

        # 6. Test C2StegoDetector DCT integration
        c2_dct = C2StegoDetector.analyze_jpeg_dct_stego(self.jpeg_bytes)
        self.assertIsNotNone(c2_dct["jsteg"])
        self.assertIsNotNone(c2_dct["f5"])
        self.assertIsNotNone(c2_dct["outguess"])

    def test_rs_steganalysis_texture_guard(self):
        # Flat solid color image: variance < 10 -> texture guard returns (False, 0.0)
        flat_arr = np.full((128, 128, 3), 128, dtype=np.uint8)
        detected, rate = perform_rs_steganalysis(flat_arr)
        self.assertFalse(detected)
        self.assertEqual(rate, 0.0)

    def test_cuckoo_json_telemetry_parser(self):
        temp_dir = tempfile.mkdtemp(prefix="cuckoo_test_")
        try:
            report_path = os.path.join(temp_dir, "report.json")
            mock_report = {
                "info": {"score": 8.2, "category": "file"},
                "target": {"file": {"name": "malicious_loader.exe"}},
                "behavior": {
                    "processes": [
                        {
                            "process_id": 1234,
                            "parent_id": 4,
                            "process_name": "malicious_loader.exe",
                            "command_line": "malicious_loader.exe --inject",
                        }
                    ]
                },
                "network": {
                    "hosts": ["198.51.100.44", "203.0.113.88"],
                    "domains": [{"domain": "c2-covert-relay.net"}],
                },
                "dropped": [
                    {
                        "name": "payload_extracted.png",
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "size": 4096,
                    }
                ],
                "signatures": [
                    {
                        "name": "injection_create_remote_thread",
                        "description": "Process injection via CreateRemoteThread",
                        "severity": 3,
                    },
                    {
                        "name": "persistence_registry_run_key",
                        "description": "Installs autorun registry key",
                        "severity": 3,
                    },
                ],
            }
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(mock_report, f)

            # Test direct parser
            telemetry = SandboxIngestionEngine.parse_cuckoo_report(report_path)
            self.assertTrue(telemetry["is_cuckoo_report"])
            self.assertEqual(telemetry["cuckoo_score"], 8.2)
            self.assertEqual(telemetry["threat_verdict"], "MALICIOUS")
            self.assertEqual(len(telemetry["process_tree"]), 1)
            self.assertIn("198.51.100.44", telemetry["network_iocs"]["ips"])
            self.assertIn("c2-covert-relay.net", telemetry["network_iocs"]["domains"])
            self.assertEqual(len(telemetry["dropped_files"]), 1)
            self.assertEqual(len(telemetry["triggered_signatures"]), 2)

            # Test sandbox directory ingestion with report.json
            findings = SandboxIngestionEngine.analyze_sandbox_artifacts(temp_dir)
            self.assertIsNotNone(findings["cuckoo_telemetry"])
            self.assertEqual(findings["overall_sandbox_verdict"], "MALICIOUS")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_chromatic_aberration_edge_aligned(self):
        # Create a synthetic image with peripheral gradient
        img = Image.new("RGB", (128, 128), color=(100, 150, 200))
        score, detected = analyze_chromatic_aberration(img)
        self.assertIsInstance(score, float)
        self.assertIsInstance(detected, bool)

    def test_noise_floor_consistency_and_composite_ai(self):
        img = Image.new("RGB", (128, 128), color=(120, 120, 120))
        detected, score = analyze_noise_floor_consistency(img)
        self.assertIsInstance(detected, bool)
        self.assertIsInstance(score, float)

        # Test composite AI detection report
        rep = analyze_ai_generation(self.jpeg_bytes, img, generate_visuals=False)
        self.assertIsInstance(rep.ai_probability_score, float)
        self.assertIn(rep.ai_verdict, ("CONFIRMED_AI", "HIGH_PROBABILITY_AI", "SUSPICIOUS_HEURISTIC", "ORGANIC_NATURAL"))


if __name__ == "__main__":
    unittest.main()
