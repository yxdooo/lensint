"""Unit tests for Scientific Benchmark Validation and C2 Stego Matrix Decoders."""
import unittest
from lensint.modules.benchmarks import BayesianForensicFusionEngine, FORENSIC_BENCHMARKS
from lensint.modules.c2_stego_decoders import C2StegoDetector


class TestBenchmarksAndDecoders(unittest.TestCase):
    def test_benchmark_dataset_metrics(self):
        self.assertIn("tampering_ela", FORENSIC_BENCHMARKS)
        self.assertIn("copy_move_cloning", FORENSIC_BENCHMARKS)
        self.assertGreater(FORENSIC_BENCHMARKS["tampering_ela"]["roc_auc"], 0.90)

    def test_bayesian_fusion_clean_vs_tampered(self):
        # Clean image inputs
        score_clean, verdict_clean, metrics_clean = BayesianForensicFusionEngine.calculate_calibrated_risk(
            ela_score=10.0,
            copy_move_detected=False,
            dqt_anomaly=False,
            cfa_anomaly=False,
            fft_ai_score=5.0,
            rs_stego_detected=False,
            chi_square_detected=False,
            metadata_anomaly=False,
            malware_threat=False,
        )
        self.assertLess(score_clean, 30.0)
        self.assertIn(verdict_clean, ("CLEAN", "LOW"))

        # Heavy tampered inputs
        score_tamp, verdict_tamp, metrics_tamp = BayesianForensicFusionEngine.calculate_calibrated_risk(
            ela_score=95.0,
            copy_move_detected=True,
            dqt_anomaly=True,
            cfa_anomaly=True,
            fft_ai_score=80.0,
            rs_stego_detected=True,
            chi_square_detected=True,
            metadata_anomaly=True,
            malware_threat=False,
        )
        self.assertGreater(score_tamp, 80.0)
        self.assertIn(verdict_tamp, ("HIGH", "CRITICAL"))
        self.assertIn("ela_disparity", metrics_tamp["contributing_indicators"])

    def test_f5_matrix_embedding_decoder(self):
        fake_jpeg = b"\xFF\xD8\xFF\xDA\x00\x08\x01\x00\x00?\x00" + b"\x01\x02\x03\x04\x05\x06\x07" * 20 + b"\xFF\xD9"
        # Run F5 matrix decoder
        res = C2StegoDetector.extract_f5_matrix_payload(fake_jpeg, k=3)
        # Should execute safely without error
        self.assertTrue(res is None or isinstance(res, dict))

    def test_outguess_decoder(self):
        fake_jpeg = b"\xFF\xD8\xFF\xDA\x00\x08\x01\x00\x00?\x00" + b"\x41\x42\x43\x44" * 40 + b"\xFF\xD9"
        res = C2StegoDetector.extract_outguess_payload(fake_jpeg, seed=1234)
        self.assertTrue(res is None or isinstance(res, dict))

    def test_dataset_benchmark_runner_youden_threshold(self):
        import tempfile
        import os
        from PIL import Image
        from lensint.modules.benchmarks import DatasetBenchmarkRunner

        tmp = tempfile.mkdtemp(prefix="lensint_bench_")
        clean_dir = os.path.join(tmp, "clean")
        tamp_dir = os.path.join(tmp, "tampered")
        os.makedirs(clean_dir, exist_ok=True)
        os.makedirs(tamp_dir, exist_ok=True)

        for i in range(3):
            Image.new("RGB", (32, 32), color=(i * 10, 0, 0)).save(os.path.join(clean_dir, f"c_{i}.png"))
            Image.new("RGB", (32, 32), color=(0, i * 10, 0)).save(os.path.join(tamp_dir, f"t_{i}.png"))

        # Detector returning 20.0 for clean and 80.0 for tampered
        def dummy_detector(p):
            return 80.0 if os.path.basename(p).startswith("t_") else 20.0

        runner = DatasetBenchmarkRunner(dummy_detector)
        metrics = runner.evaluate_directory(clean_dir, tamp_dir, default_threshold=50.0)

        self.assertEqual(metrics["total_evaluated"], 6)
        self.assertEqual(metrics["total_failed"], 0)
        self.assertEqual(metrics["roc_auc"], 1.0)
        self.assertIn("optimal_youden_threshold", metrics)
        self.assertGreaterEqual(metrics["max_youden_j_index"], 0.99)


if __name__ == "__main__":
    unittest.main()
