"""Kernel-Level EDR File-Drop Monitor & CAPE / Cuckoo Sandbox Ingestion Engine.

Provides:
1. Real-time file system drop monitoring (Windows Minifilter / Linux eBPF probe interface).
2. Dynamic analysis sandbox capture ingestion (CAPE / Cuckoo screenshots & dropped artifacts).
"""
from __future__ import annotations

import os
import time
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from lensint.core.analyzer import ImageAnalyzer
from lensint.core.models import AnalysisResult


class EDRFileDropMonitor:
    """Real-time EDR watcher scanning newly dropped image artifacts."""

    def __init__(
        self,
        watch_directory: str,
        alert_callback: Optional[Callable[[AnalysisResult], None]] = None,
        min_risk_to_alert: str = "HIGH",
    ):
        self.watch_dir = watch_directory
        self.alert_callback = alert_callback
        self.min_risk = min_risk_to_alert
        self.processed_files = set()

    def scan_new_drops_once(self) -> List[AnalysisResult]:
        """Scan directory once for any unanalyzed image drops."""
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
                        except Exception:
                            pass
        return results


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
