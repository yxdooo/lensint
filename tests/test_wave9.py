"""Unit tests for Wave 9 Deep Forensic Verification and Precision Hardening."""
import io
import unittest
from PIL import Image
import numpy as np

from lensint.modules.stego import perform_chi_square_steganalysis
from lensint.modules.stego_extract import analyze_palette_steganography
from lensint.modules.ai_detect import analyze_gan_fingerprint
from lensint.modules.tampering import detect_copy_move
from lensint.reporters.yara_gen import generate_yara_rule
from lensint.core.models import AnalysisResult


class TestWave9Remediation(unittest.TestCase):
    def test_chi_square_natural_vs_lsb_embedded(self):
        """Verify Westfeld Chi-Square correctly separates natural image from flattened LSB stego."""
        # 1. Natural structured image with uneven even/odd distribution
        y, x = np.mgrid[:100, :100]
        natural_arr = np.clip(x * 2.5 + y * 0.5, 0, 255).astype(np.uint8)
        is_stego_nat, p_nat = perform_chi_square_steganalysis(natural_arr)
        self.assertFalse(is_stego_nat)
        self.assertLess(p_nat, 0.05)

        # 2. Artificially LSB embedded image (even and odd pairs equalized)
        pairs = np.random.randint(30, 100, size=(100, 100), dtype=np.uint8) * 2
        bits = np.random.randint(0, 2, size=(100, 100), dtype=np.uint8)
        stego_arr = pairs | bits
        is_stego_emb, p_emb = perform_chi_square_steganalysis(stego_arr)
        self.assertTrue(is_stego_emb)
        self.assertGreaterEqual(p_emb, 0.10)

    def test_palette_steganography_16_color_clean(self):
        """Verify that 16-color images with unused tail palette entries do not trigger false duplicates."""
        img = Image.new("P", (64, 64), color=0)
        # Create a simple 4-color palette
        palette = [
            255, 0, 0,    # Red (idx 0)
            0, 255, 0,    # Green (idx 1)
            0, 0, 255,    # Blue (idx 2)
            255, 255, 0,  # Yellow (idx 3)
        ] + [0, 0, 0] * 252  # PIL pads with zeros
        img.putpalette(palette)
        # Draw all 4 colors in the image
        arr = np.zeros((64, 64), dtype=np.uint8)
        arr[0:16, :] = 0
        arr[16:32, :] = 1
        arr[32:48, :] = 2
        arr[48:64, :] = 3
        img = Image.fromarray(arr, mode="P")
        img.putpalette(palette)

        res = analyze_palette_steganography(img)
        self.assertFalse(res["suspicious_palette_parity"])
        self.assertEqual(res["duplicate_colors"], 0)

    def test_gan_diffusion_fingerprint_clean_natural(self):
        """Verify that natural image does not trigger GAN or excessive diffusion scores."""
        img = Image.new("RGB", (128, 128), color=(100, 150, 200))
        gan_detected, gan_score, diff_score = analyze_gan_fingerprint(img)
        self.assertFalse(gan_detected)
        self.assertLess(diff_score, 60.0)

    def test_yara_rule_no_undefined_variables(self):
        """Verify that generated YARA rule contains only active string prefixes in conditions."""
        res = AnalysisResult()
        res.integrity.file_name = "test.png"
        res.integrity.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res.malware.yara_matches = ["WebShell_Eval_Execution"]

        yara_str = generate_yara_rule(res)
        self.assertIn("rule ", yara_str)
        self.assertIn("$sig_1", yara_str)
        self.assertNotIn("$deobf_*", yara_str)
        self.assertNotIn("$cmd_*", yara_str)


if __name__ == "__main__":
    unittest.main()
