"""Unit tests for Scientific Benchmark Validation and C2 Stego Matrix Decoders."""
import unittest
from lensint.modules.benchmarks import BayesianForensicFusionEngine, FORENSIC_BENCHMARKS, LITERATURE_BASELINE_BENCHMARKS
from lensint.modules.c2_stego_decoders import C2StegoDetector


class TestBenchmarksAndDecoders(unittest.TestCase):
    def test_literature_baseline_exists(self):
        self.assertIn("tampering_ela", LITERATURE_BASELINE_BENCHMARKS)
        self.assertIn("copy_move_cloning", LITERATURE_BASELINE_BENCHMARKS)
        self.assertGreater(LITERATURE_BASELINE_BENCHMARKS["tampering_ela"]["roc_auc"], 0.90)
        self.assertIn("source", LITERATURE_BASELINE_BENCHMARKS["tampering_ela"])

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

    def test_f5_matrix_embedding_signature(self):
        fake_jpeg = b"\xFF\xD8\xFF\xDA\x00\x0C\x03\x01\x00\x02\x11\x03\x11\x00?\x00_F5_hidden_signature_here"
        res = C2StegoDetector.scan_f5_lsb_signature(fake_jpeg)
        self.assertIsNotNone(res)
        self.assertEqual(res["extracted_format"], "F5 Matrix Embedded Signature")
        self.assertEqual(res["status"], "SUSPICIOUS_SIGNATURE_ONLY")

    def test_outguess_signature(self):
        fake_jpeg = b"\xFF\xD8\xFF\xDA\x00\x0C\x03\x01\x00\x02\x11\x03\x11\x00?\x00_OUTGUESS_is_here"
        res = C2StegoDetector.scan_outguess_signature(fake_jpeg)
        self.assertIsNotNone(res)
        self.assertEqual(res["extracted_format"], "OutGuess 0.2 Signature")
        self.assertEqual(res["status"], "SUSPICIOUS_SIGNATURE_ONLY")

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
        self.assertEqual(metrics["optimal_youden_threshold"], 50.0)
        self.assertGreaterEqual(metrics["unbiased_youden_j_index"], 0.99)


if __name__ == "__main__":
    unittest.main()
