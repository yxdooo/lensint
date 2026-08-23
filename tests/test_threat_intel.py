"""Unit tests for Threat Intelligence and Reverse Image search module."""
import unittest

from lensint.modules.threat_intel import generate_threat_intel_links


class TestThreatIntelModule(unittest.TestCase):
    def test_threat_intel_link_generation(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ips = ["8.8.8.8"]
        domains = ["malicious.example.com"]
        urls = ["http://malicious.example.com/test"]

        report = generate_threat_intel_links(sha256, ips, domains, urls)

        self.assertIn("virustotal.com/gui/file", report.virustotal_file_url)
        self.assertIn("8.8.8.8", report.ip_lookups)
        self.assertIn("abuseipdb.com", report.ip_lookups["8.8.8.8"]["abuseipdb"])
        self.assertIn("Google Lens", report.reverse_image_engines)


if __name__ == "__main__":
    unittest.main()
