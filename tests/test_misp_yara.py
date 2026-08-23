"""Unit tests for MISP JSON Export and Automated YARA Rule Generation."""
import json
import os
import unittest
from PIL import Image

from lensint.core.analyzer import ImageAnalyzer
from lensint.reporters.misp_rep import render_misp_report
from lensint.reporters.yara_gen import generate_yara_rule


class TestMispAndYaraReporters(unittest.TestCase):
    def setUp(self):
        self.img = Image.new("RGB", (64, 64), color=(120, 140, 160))
        self.test_files = []

    def tearDown(self):
        for f in self.test_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    def test_misp_event_schema(self):
        img_path = "tests/test_img_misp.png"
        self.test_files.append(img_path)
        self.img.save(img_path, format="PNG")
        result = ImageAnalyzer(img_path, use_cache=False).analyze()

        misp_json = render_misp_report(result)
        data = json.loads(misp_json)

        self.assertIn("Event", data)
        self.assertIn("Attribute", data["Event"])
        self.assertIn("Tag", data["Event"])
        self.assertTrue(any(a["type"] == "sha256" for a in data["Event"]["Attribute"]))

    def test_yara_rule_generation(self):
        img_path = "tests/test_img_yara.png"
        self.test_files.append(img_path)
        self.img.save(img_path, format="PNG")
        result = ImageAnalyzer(img_path, use_cache=False).analyze()

        rule_text = generate_yara_rule(result, rule_name="Test_Suspicious_PNG")
        self.assertIn("rule Test_Suspicious_PNG", rule_text)
        self.assertIn("meta:", rule_text)
        self.assertIn("strings:", rule_text)
        self.assertIn("condition:", rule_text)
        self.assertIn(result.integrity.sha256, rule_text)


if __name__ == "__main__":
    unittest.main()
