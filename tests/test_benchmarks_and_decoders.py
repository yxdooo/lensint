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


if __name__ == "__main__":
    unittest.main()
