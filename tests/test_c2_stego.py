import io
import struct
import unittest
import zlib
from PIL import Image
from lensint.modules.c2_stego_decoders import C2StegoDetector


class TestC2StegoModule(unittest.TestCase):
    def setUp(self):
        img = Image.new("RGB", (32, 32), color=(0, 255, 0))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        self.png_bytes = buf.getvalue()

    def test_png_chunk_covert_crc32_tamper(self):
        # Inject an anomalous chunk with invalid CRC32 into the PNG
        custom_chunk_type = b"coVT"
        custom_chunk_data = b"C2_COMMAND_EXEC_PAYLOAD"
        bad_crc = 0xDEADBEEF
        injected_chunk = (
            struct.pack(">I", len(custom_chunk_data))
            + custom_chunk_type
            + custom_chunk_data
            + struct.pack(">I", bad_crc)
        )

        tampered_png = self.png_bytes[:33] + injected_chunk + self.png_bytes[33:]
        result = C2StegoDetector.analyze_png_chunks(tampered_png)

        self.assertTrue(result["is_png"])
        self.assertGreaterEqual(len(result["non_standard_chunks"]), 1)
        self.assertGreaterEqual(len(result["crc_tampered_chunks"]), 1)

    def test_frequency_stego_markers(self):
        fake_jpeg_jsteg = b"\xFF\xD8\xFF\xE0" + b"\x00" * 20 + b"\x00\x00\x00\x00\x00\x00\x00\x00JSTEG" + b"\xFF\xD9"
        markers = C2StegoDetector.analyze_frequency_stego_markers(fake_jpeg_jsteg)
        self.assertGreaterEqual(len(markers), 1)
        self.assertIn("JSteg", markers[0]["tool"])


if __name__ == "__main__":
    unittest.main()
