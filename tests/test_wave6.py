import io
import json
import os
import struct
import tempfile
import pytest
from PIL import Image

from lensint.core.analyzer import ImageAnalyzer
from lensint.core.models import AnalysisResult
from lensint.modules.benchmarks import BayesianForensicFusionEngine
from lensint.modules.c2_stego_decoders import C2StegoDetector
from lensint.modules.edr_sandbox import SandboxIngestionEngine
from lensint.modules.jpeg_dct import (
    JPEGDCTExtractor,
    estimate_jsteg_payload,
    parse_jpeg_dct_coefficients,
)
from lensint.modules.memory_forensics import MemoryForensicsEngine


class TestWave6ForensicUpgrades:

    def test_jpeg_dct_dri_and_status(self):
        """Verify DRI parsing, detailed status reporting, and baseline sequential extraction."""
        img = Image.new("RGB", (64, 64), color=(120, 150, 180))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        raw_jpeg = buf.getvalue()

        extractor = JPEGDCTExtractor(raw_jpeg)
        res = extractor.extract_detailed()
        assert res.status in ("COMPLETE", "PARTIAL")
        assert res.image_width == 64
        assert res.image_height == 64
        assert len(res.blocks) > 0

    def test_jpeg_dct_malformed_and_progressive_rejection(self):
        """Verify strict rejection of non-baseline / progressive markers and malformed SOF0."""
        prog_jpeg = b"\xFF\xD8\xFF\xC2\x00\x11\x08\x00\x40\x00\x40\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01\xFF\xD9"
        res = JPEGDCTExtractor(prog_jpeg).extract_detailed()
        assert res.status == "UNSUPPORTED_PROGRESSIVE_OR_ARITHMETIC"
        assert len(res.blocks) == 0

        bad_data = b"\xFF\xD8\xFF\xC0\x00\x05\x08\x00"
        res2 = JPEGDCTExtractor(bad_data).extract_detailed()
        assert res2.status in ("MALFORMED_SOF0", "ERROR", "NOT_BASELINE_JPEG")

    def test_png_semantic_validation_and_idat_fragmentation(self):
        """Verify PNG semantic validation (IHDR length, color types, eXIf chunk, IDAT fragmentation)."""
        img = Image.new("RGBA", (32, 32), color=(255, 0, 0, 255))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        raw_png = buf.getvalue()

        analysis = C2StegoDetector.analyze_png_chunks(raw_png)
        assert analysis["is_png"] is True
        assert len(analysis["semantic_violations"]) == 0
        assert analysis["idat_fragmentation_detected"] is False

        corrupt_ihdr = bytearray(raw_png)
        corrupt_ihdr[8:12] = struct.pack(">I", 10)  # Length 10 instead of 13
        analysis_corrupt = C2StegoDetector.analyze_png_chunks(bytes(corrupt_ihdr))
        assert any("IHDR" in v for v in analysis_corrupt["semantic_violations"])

    def test_cuckoo_ip_vs_domain_classification(self):
        """Verify Cuckoo report IP addresses vs domain hostnames are strictly separated."""
        report_data = {
            "info": {"score": 8.5},
            "target": {"file": {"name": "sample.exe"}},
            "behavior": {
                "processes": [
                    {"process_id": 1024, "parent_id": 4, "process_name": "malware.exe", "command_line": "malware.exe -drop"}
                ]
            },
            "network": {
                "hosts": [
                    "192.168.1.50",
                    "c2.malicious-domain.com",
                    {"ip": "10.0.0.1"},
                    "exfil.cloud-storage.net"
                ],
                "domains": [
                    {"domain": "api.telegram.org"},
                    "cdn.discordapp.com"
                ]
            },
            "dropped": [
                {"name": "dropped_payload.png", "sha256": "abc123def456", "size": 4096}
            ],
            "signatures": [
                {"name": "injection", "description": "Process injection detected", "severity": 3}
            ]
        }

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = f.name

        try:
            telemetry = SandboxIngestionEngine.parse_cuckoo_report(temp_path)
            assert telemetry["is_cuckoo_report"] is True
            assert telemetry["threat_verdict"] == "MALICIOUS"
            assert "192.168.1.50" in telemetry["network_iocs"]["ips"]
            assert "10.0.0.1" in telemetry["network_iocs"]["ips"]
            assert "c2.malicious-domain.com" in telemetry["network_iocs"]["domains"]
            assert "exfil.cloud-storage.net" in telemetry["network_iocs"]["domains"]
            assert "api.telegram.org" in telemetry["network_iocs"]["domains"]
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_sandbox_multi_report_and_hash_correlation(self):
        """Verify multiple Cuckoo reports are retained and dropped files cross-correlate with artifacts."""
        with tempfile.TemporaryDirectory() as temp_dir:
            img = Image.new("RGB", (50, 50), color=(100, 100, 100))
            img_path = os.path.join(temp_dir, "screen_01.png")
            img.save(img_path)

            import hashlib
            with open(img_path, "rb") as f:
                img_sha256 = hashlib.sha256(f.read()).hexdigest()

            rep1 = {
                "info": {"score": 5.0},
                "signatures": [{"name": "sig1", "severity": 2}],
                "dropped": [{"name": "screen_01.png", "sha256": img_sha256, "size": 1000}],
            }
            with open(os.path.join(temp_dir, "report.json"), "w") as f:
                json.dump(rep1, f)

            rep2 = {
                "info": {"score": 8.0},
                "signatures": [{"name": "sig2", "severity": 3}],
                "dropped": [],
            }
            with open(os.path.join(temp_dir, "report2.json"), "w") as f:
                json.dump(rep2, f)

            findings = SandboxIngestionEngine.analyze_sandbox_artifacts(temp_dir)
            assert len(findings["all_cuckoo_reports"]) == 2
            assert findings["cuckoo_telemetry"]["cuckoo_score"] == 8.0
            assert len(findings["correlated_artifacts"]) == 1
            assert findings["correlated_artifacts"][0]["sha256"] == img_sha256
            assert findings["overall_sandbox_verdict"] == "MALICIOUS"

    def test_bayesian_fusion_structured_flags(self):
        """Verify Bayesian fusion processes structured C2 stego and prompt injection flags."""
        score, verdict, telemetry = BayesianForensicFusionEngine.calculate_calibrated_risk(
            ela_score=10.0,
            copy_move_detected=False,
            dqt_anomaly=False,
            cfa_anomaly=False,
            fft_ai_score=5.0,
            rs_stego_detected=False,
            chi_square_detected=False,
            metadata_anomaly=False,
            malware_threat=False,
            confirmed_payload=False,
            c2_stego_detected=True,
            prompt_injection=True,
            prior_probability=0.10,
        )
        assert score > 50.0
        assert "c2_stego_signature" in telemetry["contributing_indicators"]
        assert "prompt_injection" in telemetry["contributing_indicators"]

    def test_memory_forensics_balanced_carve_order(self):
        """Verify memory carver extracts images across multiple formats and maintains offset ordering."""
        engine = MemoryForensicsEngine()
        
        img_png = Image.new("RGBA", (16, 16), color=(255, 0, 0, 255))
        pbuf = io.BytesIO(); img_png.save(pbuf, format="PNG"); png_bytes = pbuf.getvalue()

        img_jpg = Image.new("RGB", (16, 16), color=(0, 255, 0))
        jbuf = io.BytesIO(); img_jpg.save(jbuf, format="JPEG"); jpg_bytes = jbuf.getvalue()

        raw_mem = png_bytes + (b"\x00" * 500) + jpg_bytes
        carved = engine.carve_memory_stream(raw_mem, max_images=10)
        assert len(carved) >= 2
        assert carved[0]["format"] == "PNG"
        assert carved[0]["offset"] == 0
        assert carved[1]["format"] == "JPEG"
        assert carved[1]["offset"] > 0
