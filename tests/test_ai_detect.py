"""Unit tests for AI Generation, 2D FFT Spectrum, and PRNU Sensor detection."""
import unittest
from PIL import Image

from lensint.modules.ai_detect import (
    analyze_ai_generation,
    calculate_fft_spectrum,
    analyze_prnu_sensor_noise,
    detect_inpainting_anomalies,
)


class TestAIDetectModule(unittest.TestCase):
    def test_prnu_sensor_noise_evaluation(self):
        img = Image.new("RGB", (128, 128), color=(100, 100, 100))
        present, score = analyze_prnu_sensor_noise(img)
        self.assertIsInstance(present, bool)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)

    def test_inpainting_anomaly_score(self):
        img = Image.new("RGB", (128, 128), color=(80, 120, 160))
        score = detect_inpainting_anomalies(img)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)

    def test_fft_spectrum_calculation(self):
        img = Image.new("RGB", (128, 128), color=(50, 100, 150))
        norm_vis, peak_ratio, score, suspected = calculate_fft_spectrum(img)
        self.assertGreaterEqual(score, 0.0)
        self.assertGreaterEqual(peak_ratio, 0.0)
        self.assertIsInstance(suspected, (bool, type(False)))

    def test_stable_diffusion_metadata_detection(self):
        raw_png = b"\x89PNG\r\n\x1a\n" + b"tEXtparameters\x00masterpiece, best quality, cyberpunk neon city\nNegative prompt: blurry\nSteps: 30, Sampler: DPM++ 2M, CFG scale: 7, Seed: 123456789"
        img = Image.new("RGB", (64, 64), color=(10, 10, 10))
        report = analyze_ai_generation(raw_png, img, generate_visuals=False)
        self.assertEqual(report.ai_verdict, "CONFIRMED_AI")
        self.assertIn("Stable Diffusion", report.ai_generator_name)


if __name__ == "__main__":
    unittest.main()
