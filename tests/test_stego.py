"""Unit tests for Steganography, RS Steganalysis, and Overlay extraction."""
import io
import unittest
from PIL import Image

from lensint.modules.stego import (
    analyze_stego,
    detect_overlay_data,
    perform_rs_steganalysis,
    scan_stego_tool_signatures,
    _calculate_entropy,
)


class TestStegoModule(unittest.TestCase):
    def test_overlay_data_extraction(self):
        # Create a valid JPEG and append hidden overlay
        img = Image.new("RGB", (64, 64), color=(100, 150, 200))
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        jpeg_bytes = buf.getvalue()

        payload_expected = b"CUSTOM_SECRET_PAYLOAD_12345"
        carrier = jpeg_bytes + payload_expected

        has_ov, off, size, payload = detect_overlay_data(carrier)
        self.assertTrue(has_ov)
        self.assertEqual(payload, payload_expected)
        self.assertEqual(size, len(payload_expected))
        self.assertEqual(off, len(jpeg_bytes))

    def test_stego_tool_signatures(self):
        raw_data = b"Some prefix..." + b"OPENSTEGO" + b"...trailer"
        sigs = scan_stego_tool_signatures(raw_data)
        self.assertGreater(len(sigs), 0)
        self.assertIn("OpenStego", sigs[0])

    def test_entropy_calculation(self):
        data = b"ABCDEFGHIJK" * 50
        ent = _calculate_entropy(data)
        self.assertGreaterEqual(ent, 0.0)
        self.assertLessEqual(ent, 8.0)

    def test_full_stego_analysis(self):
        img = Image.new("RGB", (64, 64), color=(100, 150, 200))
        raw_png = b"\x89PNG\r\n\x1a\n" + b"OPENSTEGO" + b"IEND\xaeB`\x82"
        report = analyze_stego(raw_png, img, generate_visuals=False)
        self.assertIn("Red", report.lsb_entropy)
        self.assertIn("Average", report.lsb_entropy)
        self.assertGreater(len(report.stego_tool_signatures), 0)


if __name__ == "__main__":
    unittest.main()
