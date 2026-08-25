"""Unit tests for Console, JSON, HTML, and STIX 2.1 reporting formats."""
import json
import os
import shutil
import tempfile
import unittest
from PIL import Image

from lensint.core.analyzer import ImageAnalyzer
from lensint.reporters.html_rep import render_html_report
from lensint.reporters.json_rep import render_json_report
from lensint.reporters.stix_rep import render_stix_report


class TestReportersModule(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.img_path = os.path.join(self.tmp_dir, "test.png")
        img = Image.new("RGB", (64, 64), color=(50, 100, 150))
        img.save(self.img_path, format="PNG")

        self.result = ImageAnalyzer(self.img_path, use_cache=False).analyze()

    def tearDown(self):
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_json_reporter_validity(self):
        json_str = render_json_report(self.result)
        data = json.loads(json_str)
        self.assertIn("target_path", data)
        self.assertIn("integrity", data)
        self.assertIn("overall_risk_score", data)

    def test_html_reporter_generation(self):
        html_str = render_html_report(self.result)
        self.assertIn("<!DOCTYPE html>", html_str)
        self.assertIn("Lensint Forensics Report", html_str)
        self.assertIn("SHA-256", html_str)

    def test_stix_reporter_bundle_format(self):
        stix_str = render_stix_report(self.result)
        bundle = json.loads(stix_str)
        self.assertEqual(bundle["type"], "bundle")
        self.assertIn("objects", bundle)
        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("file", types)


if __name__ == "__main__":
    unittest.main()
