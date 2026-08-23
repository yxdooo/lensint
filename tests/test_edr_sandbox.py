import os
import shutil
import tempfile
import unittest
from PIL import Image
from lensint.modules.edr_sandbox import EDRFileDropMonitor, SandboxIngestionEngine


class TestEDRSandboxModule(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="lensint_edr_test_")

        # Create a test image inside the temporary directory
        self.img_path = os.path.join(self.test_dir, "screenshot_01.png")
        img = Image.new("RGB", (100, 100), color=(200, 100, 50))
        img.save(self.img_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_edr_file_drop_monitor(self):
        monitor = EDRFileDropMonitor(self.test_dir)
        results = monitor.scan_new_drops_once()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].integrity.file_name, "screenshot_01.png")

    def test_sandbox_ingestion_engine(self):
        findings = SandboxIngestionEngine.analyze_sandbox_artifacts(self.test_dir)
        self.assertEqual(findings["screenshots_analyzed"], 1)
        self.assertIn(findings["overall_sandbox_verdict"], ("CLEAN", "SUSPICIOUS", "MALICIOUS"))


if __name__ == "__main__":
    unittest.main()
