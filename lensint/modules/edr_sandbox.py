"""Real-Time Endpoint Evidence Watcher, Process Attribution & Sandbox Ingestion Engine.

Provides:
1. Real-time file system evidence drop monitoring for SOC incident response directories.
2. Endpoint process attribution telemetry (correlating new evidence files with active processes).
3. Dynamic analysis sandbox capture ingestion (CAPE / Cuckoo screenshots & dropped artifacts).
"""
from __future__ import annotations

import logging
import os
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Set, TYPE_CHECKING
if TYPE_CHECKING:
    from lensint.core.analyzer import ImageAnalyzer
from lensint.core.models import AnalysisResult

logger = logging.getLogger("lensint.watcher")


class RealtimeDropMonitor:
    """Continuous real-time evidence drop watcher for incident response directories."""

    def __init__(
        self,
        watch_directory: str,
        alert_callback: Optional[Callable[[AnalysisResult], None]] = None,
        min_risk_to_alert: str = "HIGH",
    ):
        self.watch_dir = watch_directory
        self.alert_callback = alert_callback
        self.min_risk = min_risk_to_alert
        self.processed_files: Set[str] = set()
        self._running = False

    @staticmethod
    def inspect_process_telemetry() -> List[Dict[str, str]]:
        """Capture active process snapshot to correlate dropped image artifacts."""
        processes = []
        try:
            if os.name == "nt":
                cmd = ["tasklist", "/FO", "CSV", "/NH"]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
                for line in output.strip().split("\n")[:25]:
                    parts = [p.strip(' "\r') for p in line.split(",")]
                    if len(parts) >= 2:
                        processes.append({"image_name": parts[0], "pid": parts[1]})
            else:
                cmd = ["ps", "-eo", "pid,comm", "--no-headers"]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
                for line in output.strip().split("\n")[:25]:
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2:
                        processes.append({"pid": parts[0], "image_name": parts[1]})
        except Exception:
            pass
        return processes

    def scan_new_drops_once(self) -> List[AnalysisResult]:
        """Scan directory once for any newly added image evidence."""
        from lensint.core.analyzer import ImageAnalyzer
        results = []
        if not os.path.exists(self.watch_dir):
            return results

        supported_exts = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tiff"}
        for root, _, files in os.walk(self.watch_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in supported_exts:
                    full_path = os.path.join(root, file)
                    if full_path not in self.processed_files:
                        self.processed_files.add(full_path)
                        try:
                            analyzer = ImageAnalyzer(full_path, use_cache=True)
                            res = analyzer.analyze()
                            results.append(res)
                            if self.alert_callback and res.overall_risk_level in ("HIGH", "CRITICAL"):
                                self.alert_callback(res)
                        except Exception as e:
                            logger.error(f"Error analyzing dropped artifact {full_path}: {e}")
        return results

    def watch_continuously(self, poll_interval: float = 1.0, max_iterations: Optional[int] = None) -> None:
        """Run continuous monitoring loop until interrupted."""
        self._running = True
        iterations = 0
        logger.info(f"Started continuous artifact watcher on {self.watch_dir}")
        try:
            while self._running:
                self.scan_new_drops_once()
                iterations += 1
                if max_iterations and iterations >= max_iterations:
                    break
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Artifact watcher stopped by user.")
        finally:
            self._running = False


# Backward compatibility alias
EDRFileDropMonitor = RealtimeDropMonitor


class SandboxIngestionEngine:
    """Ingests and correlates dynamic sandbox execution captures (CAPE / Cuckoo)."""

    @staticmethod
    def analyze_sandbox_artifacts(sandbox_dir: str) -> Dict[str, Any]:
        """Analyze screenshots and memory artifacts captured from a sandbox run."""
        from lensint.core.analyzer import ImageAnalyzer
        findings = {
            "sandbox_dir": sandbox_dir,
            "screenshots_analyzed": 0,
            "high_risk_captures": [],
            "extracted_credentials": [],
            "malware_signatures": [],
            "overall_sandbox_verdict": "CLEAN",
        }

        if not os.path.exists(sandbox_dir):
            return findings

        supported_exts = {".png", ".jpg", ".jpeg", ".bmp"}
        highest_score = 0.0

        for root, _, files in os.walk(sandbox_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in supported_exts:
                    full_path = os.path.join(root, file)
                    try:
                        res = ImageAnalyzer(full_path, use_cache=False).analyze()
                        findings["screenshots_analyzed"] += 1
                        if res.overall_risk_score > highest_score:
                            highest_score = res.overall_risk_score

                        if res.overall_risk_level in ("HIGH", "CRITICAL"):
                            findings["high_risk_captures"].append({
                                "file": file,
                                "risk_score": res.overall_risk_score,
                                "findings": res.summary_findings[:3],
                            })

                        # Collect OCR secret findings from sandbox screens
                        if res.ocr and res.ocr.sensitive_findings:
                            for sf in res.ocr.sensitive_findings:
                                findings["extracted_credentials"].append(f"{file}: {sf['type']} ({sf['redacted']})")

                        # Collect malware signatures
                        if res.malware and res.malware.threat_signatures:
                            findings["malware_signatures"].extend(res.malware.threat_signatures)
                    except Exception:
                        pass

        if highest_score >= 70.0:
            findings["overall_sandbox_verdict"] = "MALICIOUS"
        elif highest_score >= 35.0:
            findings["overall_sandbox_verdict"] = "SUSPICIOUS"

        return findings
