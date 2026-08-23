"""Unit tests for Courtroom-Grade Tampering Forensics (ELA, Copy-Move, Splice, DQT)."""
import unittest
from PIL import Image
import numpy as np

from lensint.modules.tampering import (
    analyze_tampering,
    perform_ela,
    analyze_splice_detection,
    detect_copy_move,
)


class TestTamperingModule(unittest.TestCase):
    def test_ela_analysis(self):
        img = Image.new("RGB", (200, 200), color=(150, 100, 50))
        # Draw some variation
        arr = np.array(img)
        arr[50:100, 50:100] = (255, 255, 0)
        img_var = Image.fromarray(arr)

        vis, mean_d, max_d, std_d, score, reason = perform_ela(img_var, quality=90)
        self.assertGreaterEqual(score, 0.0)
        self.assertGreaterEqual(mean_d, 0.0)

    def test_splice_detection(self):
        img = Image.new("RGB", (128, 128), color=(100, 100, 100))
        detected, conf, b64_map, boxes = analyze_splice_detection(img, generate_visuals=False)
        self.assertIsInstance(detected, bool)
        self.assertIsInstance(conf, float)
        self.assertIsInstance(boxes, list)

    def test_copy_move_cloning_detection(self):
        # Create image with duplicated pattern
        img = Image.new("RGB", (256, 256), color=(200, 200, 200))
        arr = np.array(img)
        # Duplicate high-contrast block
        pattern = np.random.randint(0, 255, (40, 40, 3), dtype=np.uint8)
        arr[20:60, 20:60] = pattern
        arr[120:160, 120:160] = pattern
        img_dup = Image.fromarray(arr)

        detected, count, vis_img = detect_copy_move(img_dup)
        self.assertIsInstance(detected, bool)
        self.assertIsInstance(count, int)

    def test_full_tampering_analysis(self):
        img = Image.new("RGB", (128, 128), color=(120, 120, 120))
        raw_jpeg = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        report = analyze_tampering(img, raw_jpeg, generate_visuals=False)
        self.assertIsNotNone(report.suspicion_level)


if __name__ == "__main__":
    unittest.main()
