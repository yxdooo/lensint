"""Unit tests for Configuration Management and Forensic Chain of Custody Audit Trail."""
import os
import shutil
import tempfile
import unittest
from PIL import Image

from lensint.config import LensintConfig
from lensint.core.analyzer import ImageAnalyzer
from lensint.audit import ForensicAuditLogger


class TestAuditAndConfig(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.img_path = os.path.join(self.tmp_dir, "test.png")
        img = Image.new("RGB", (64, 64), color=(50, 100, 150))
        img.save(self.img_path, format="PNG")
        self.result = ImageAnalyzer(self.img_path, use_cache=False).analyze()

    def tearDown(self):
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_config_defaults(self):
        cfg = LensintConfig()
        self.assertGreater(cfg.max_upload_size_mb, 0)
        self.assertEqual(cfg.max_upload_size_bytes, cfg.max_upload_size_mb * 1024 * 1024)
        d = cfg.to_dict()
        self.assertIn("server_port", d)
        self.assertIn("cache_enabled", d)

    def test_audit_record_creation_and_verification(self):
        custom_log = os.path.join(self.tmp_dir, "audit_ledger.jsonl")
        logger = ForensicAuditLogger()
        entry = logger.record_analysis(
            result=self.result,
            case_id="CASE-2026-TEST",
            examiner="SecAnalyst",
            notes="Automated unit test run",
            custom_log_path=custom_log,
        )

        self.assertIn("audit_seal_sha256", entry)
        self.assertEqual(entry["chain_of_custody"]["case_id"], "CASE-2026-TEST")
        self.assertEqual(entry["chain_of_custody"]["examiner"], "SecAnalyst")
        self.assertTrue(os.path.exists(custom_log))

        # Cryptographic seal verification
        is_valid = ForensicAuditLogger.verify_audit_record(entry)
        self.assertTrue(is_valid)

        # Tampered entry must fail verification
        entry_tampered = dict(entry)
        entry_tampered["forensic_verdict"]["risk_score"] = 999.9
        self.assertFalse(ForensicAuditLogger.verify_audit_record(entry_tampered))

    def test_audit_chain_hash_linking(self):
        custom_log = os.path.join(self.tmp_dir, "chained_ledger.jsonl")
        logger = ForensicAuditLogger()
        
        # Record 1 (Genesis)
        e1 = logger.record_analysis(self.result, case_id="CASE-1", custom_log_path=custom_log)
        self.assertEqual(e1["previous_record_seal"], "0" * 64)
        
        # Record 2 (Chained to 1)
        e2 = logger.record_analysis(self.result, case_id="CASE-2", custom_log_path=custom_log)
        self.assertEqual(e2["previous_record_seal"], e1["audit_seal_sha256"])
        
        # Verify complete chain
        valid, count, err = ForensicAuditLogger.verify_audit_chain(custom_log)
        self.assertTrue(valid)
        self.assertEqual(count, 2)
        self.assertIsNone(err)


if __name__ == "__main__":
    unittest.main()
