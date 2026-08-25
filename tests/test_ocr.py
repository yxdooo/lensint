"""Unit tests for OCR and Sensitive Data / Secret Leak Hunter."""
import unittest
from PIL import Image

from lensint.modules.ocr_scan import (
    analyze_ocr,
    scan_sensitive_leaks,
    _luhn_checksum,
    _validate_tc_kimlik,
)


class TestOCRModule(unittest.TestCase):
    def test_luhn_credit_card_checksum(self):
        # Valid test Visa number (4532 ... 1111)
        self.assertTrue(_luhn_checksum("4532015112830366"))
        self.assertFalse(_luhn_checksum("4532015112830367"))

    def test_tc_kimlik_validation(self):
        # Valid TC algorithmic checksum example
        self.assertTrue(_validate_tc_kimlik("10000000146"))
        self.assertFalse(_validate_tc_kimlik("10000000147"))
        self.assertFalse(_validate_tc_kimlik("01234567890"))

    def test_secret_leak_scanner_aws_github_keys(self):
        leak_text = """
        AWS_SECRET_CONFIG:
        aws_access_key_id = AKIAIOSFODNN7EXAMPLE
        token: ghp_1234567890abcdefghijklmnopqrstuvwxyz
        sk-proj-1234567890abcdefghijklmnopqrstuvwxyz123456
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA0Y...
        -----END RSA PRIVATE KEY-----
        """
        results = scan_sensitive_leaks(leak_text)
        self.assertGreater(len(results["api_keys"]), 0)
        self.assertGreater(len(results["private_keys"]), 0)
        self.assertTrue(any("AKIA" in f["value"] for f in results["findings"]))

    def test_analyze_ocr_fallback(self):
        img = Image.new("RGB", (100, 50), color=(255, 255, 255))
        sample_text = "AKIA1234567890ABCDEF password = 'super_secret_db_pass'"
        report = analyze_ocr(img, raw_text_fallback=sample_text)
        self.assertTrue(report.ocr_performed)
        self.assertTrue(report.text_detected)
        self.assertGreater(len(report.sensitive_findings), 0)


if __name__ == "__main__":
    unittest.main()
