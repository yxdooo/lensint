"""Unit tests for Strings & IOC Extraction module."""
import unittest

from lensint.modules.strings_scan import analyze_strings


class TestStringsModule(unittest.TestCase):
    def test_ioc_extraction(self):
        raw_content = b"""
        Connecting to C2 at http://192.168.1.100:8080/beacon
        Secondary host: 10.0.0.5
        Backup darknet: http://hiddenservice7xyz.onion/admin
        Contact: attacker@evil-corp.com
        Bitcoin reward: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        Execute: cmd.exe /c powershell -enc dGVzdA==
        """
        report = analyze_strings(raw_content, min_len=4)

        iocs = report.iocs_detected
        self.assertIn("192.168.1.100", iocs["ipv4"])
        self.assertIn("10.0.0.5", iocs["ipv4"])
        self.assertTrue(any(".onion" in u for u in iocs["urls"]))
        self.assertIn("attacker@evil-corp.com", iocs["emails"])
        self.assertIn("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", iocs["crypto_wallets"])
        self.assertTrue(len(iocs["shell_commands"]) > 0)


if __name__ == "__main__":
    unittest.main()
