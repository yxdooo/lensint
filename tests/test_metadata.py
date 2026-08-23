"""Unit tests for Metadata, EXIF, IPTC, XMP, and Footprint analysis."""
import unittest
from PIL import Image
import io

from lensint.modules.metadata import (
    analyze_metadata,
    _detect_social_media_provenance,
    _calculate_ssim,
    _check_thumbnail_mismatch,
)


class TestMetadataModule(unittest.TestCase):
    def test_social_media_provenance_whatsapp(self):
        # 1600px image with no EXIF headers
        img = Image.new("RGB", (1600, 1200), color=(100, 100, 100))
        raw_jpeg = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        prov = _detect_social_media_provenance(raw_jpeg, img, has_exif=False)
        self.assertIsNotNone(prov)
        self.assertIn("WhatsApp", prov)

    def test_ssim_calculation_identical(self):
        img1 = Image.new("RGB", (64, 64), color=(128, 128, 128))
        img2 = Image.new("RGB", (64, 64), color=(128, 128, 128))
        score = _calculate_ssim(img1, img2)
        self.assertAlmostEqual(score, 1.0, places=2)

    def test_ssim_calculation_different(self):
        img1 = Image.new("RGB", (64, 64), color=(0, 0, 0))
        img2 = Image.new("RGB", (64, 64), color=(255, 255, 255))
        score = _calculate_ssim(img1, img2)
        self.assertLess(score, 0.5)

    def test_xmp_and_iptc_analysis(self):
        raw_bytes = b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreatorTool="Adobe Photoshop 2024"/></rdf:RDF></x:xmpmeta>'
        report = analyze_metadata(raw_bytes, None)
        self.assertTrue(report.xmp_present)
        self.assertIn("Photoshop", " ".join(report.software_footprint_findings))


if __name__ == "__main__":
    unittest.main()
