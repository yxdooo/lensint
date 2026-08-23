import io
import unittest
from PIL import Image
from lensint.modules.memory_forensics import MemoryForensicsEngine, VolatilityLensintPlugin


class TestMemoryForensicsModule(unittest.TestCase):
    def setUp(self):
        # Create a small valid PNG in memory
        img = Image.new("RGB", (64, 64), color=(255, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        self.png_bytes = buf.getvalue()

        # Create a small valid JPEG in memory
        buf_jpg = io.BytesIO()
        img.save(buf_jpg, format="JPEG")
        self.jpg_bytes = buf_jpg.getvalue()

    def test_carve_memory_stream_png_and_jpeg(self):
        # Simulate unallocated RAM noise surrounding image allocations
        ram_noise_prefix = b"\x00\x11\x22\x33\x44" * 100
        ram_noise_mid = b"\xAA\xBB\xCC\xDD\xEE" * 100
        ram_noise_suffix = b"\x55\x66\x77\x88\x99" * 100

        mock_ram_dump = ram_noise_prefix + self.png_bytes + ram_noise_mid + self.jpg_bytes + ram_noise_suffix

        engine = MemoryForensicsEngine()
        carved = engine.carve_memory_stream(mock_ram_dump)

        self.assertGreaterEqual(len(carved), 2)
        formats = [c["format"] for c in carved]
        self.assertIn("PNG", formats)
        self.assertIn("JPEG", formats)

    def test_volatility_plugin_interface(self):
        ram_stream = b"\x00" * 50 + self.png_bytes + b"\x00" * 50
        results = VolatilityLensintPlugin.scan_layer_pages(ram_stream)
        self.assertGreaterEqual(len(results), 1)
        self.assertEqual(results[0]["format"], "PNG")


if __name__ == "__main__":
    unittest.main()
