"""Unit tests for File Integrity & Cryptographic Hashing module."""
import os
import unittest
from PIL import Image
import io

from lensint.modules.integrity import analyze_integrity


class TestIntegrityModule(unittest.TestCase):
    def test_png_integrity_and_hashes(self):
        # Create a valid PNG in memory
        img = Image.new("RGB", (100, 100), color=(255, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        raw_bytes = buf.getvalue()

        report = analyze_integrity("sample.png", raw_bytes, img)

        self.assertEqual(report.detected_format, "PNG")
        self.assertEqual(report.detected_mime, "image/png")
        self.assertFalse(report.extension_mismatch)
        self.assertFalse(report.is_corrupt_or_truncated)
        self.assertEqual(len(report.sha256), 64)
        self.assertEqual(len(report.md5), 32)
        self.assertEqual(len(report.sha1), 40)
        self.assertEqual(len(report.sha512), 128)
        self.assertEqual(report.dimensions, (100, 100))

    def test_extension_mismatch_spoofing(self):
        # Disguised PHP script with .jpg extension
        raw_bytes = b"<?php echo 'malicious webshell'; ?>"
        report = analyze_integrity("innocent.jpg", raw_bytes, None)

        self.assertTrue(report.extension_mismatch)
        self.assertNotEqual(report.detected_format, "JPEG")

    def test_corrupted_container_detection(self):
        # Truncated JPEG header without data
        raw_bytes = b"\xFF\xD8\xFF\xE0"
        report = analyze_integrity("corrupt.jpg", raw_bytes, None)

        self.assertTrue(report.is_corrupt_or_truncated)


if __name__ == "__main__":
    unittest.main()
