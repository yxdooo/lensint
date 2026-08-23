"""Directory Watcher, Process Attribution & Sandbox Ingestion Engine.

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
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TYPE_CHECKING
if TYPE_CHECKING:
    from lensint.core.analyzer import ImageAnalyzer
from lensint.core.models import AnalysisResult

logger = logging.getLogger("lensint.watcher")


class DirectoryWatcher:
    """Continuous real-time evidence drop watcher for incident response directories."""

    def __init__(
        self,
        watch_directory: str,
        alert_callback: Optional[Callable[[AnalysisResult], None]] = None,
        min_risk_to_alert: str = "HIGH",
    ):
        import threading
        from collections import OrderedDict
        self.watch_dir = watch_directory
        self.alert_callback = alert_callback
        self.min_risk = min_risk_to_alert
        # Stores (inode, mtime, size) -> timestamp to prevent memory leak (True LRU Cache)
        self.processed_files: OrderedDict[Tuple[int, float, int], float] = OrderedDict()
        self._lock = threading.Lock()
        self._running = False

    @staticmethod
    def inspect_process_telemetry() -> List[Dict[str, str]]:
        """Capture active process snapshot.
        
        NOTE: This is a point-in-time polling-based snapshot (`tasklist` / `ps`).
        It does NOT provide true kernel-level ETW, Sysmon, or inotify attribution. 
        Short-lived writer processes may be missed.
        """
        processes = []
        try:
            if os.name == "nt":
                cmd = ["tasklist", "/FO", "CSV", "/NH"]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
                for line in output.strip().split("\n")[:100]:
                    parts = [p.strip(' "\r') for p in line.split(",")]
                    if len(parts) >= 2:
                        processes.append({"image_name": parts[0], "pid": parts[1]})
            else:
                cmd = ["ps", "-eo", "pid,comm", "--no-headers"]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
                for line in output.strip().split("\n")[:100]:
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2:
                        processes.append({"pid": parts[0], "image_name": parts[1]})
        except Exception:
            pass
        return processes

    def _is_file_stable(self, path: str) -> bool:
        """Check if file has finished writing by comparing size over an observation window."""
        try:
            initial_size = os.path.getsize(path)
            time.sleep(0.5)
            final_size = os.path.getsize(path)
            if initial_size != final_size or final_size == 0:
                return False
            # Check for basic read/write availability
            with open(path, "ab"):
                pass
            return True
        except OSError:
            return False

    def scan_new_drops_once(self) -> List[AnalysisResult]:
        """Scan directory once for any newly added image evidence."""
        from lensint.core.analyzer import ImageAnalyzer
        results = []
        if not os.path.exists(self.watch_dir):
            return results

        # Clean up processed_files LRU to prevent memory leak
        with self._lock:
            while len(self.processed_files) > 10000:
                self.processed_files.popitem(last=False)

        supported_exts = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tiff"}
        for root, _, files in os.walk(self.watch_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in supported_exts:
                    full_path = os.path.join(root, file)
                    try:
                        stat = os.stat(full_path)
                        # Fingerprint: inode, mtime, size
                        file_fingerprint = (stat.st_ino, stat.st_mtime, stat.st_size)
                        
                        with self._lock:
                            is_processed = file_fingerprint in self.processed_files

                        if not is_processed:
                            if not self._is_file_stable(full_path):
                                continue  # Wait for the file to finish writing
                                
                            with self._lock:
                                self.processed_files[file_fingerprint] = time.time()
                                self.processed_files.move_to_end(file_fingerprint)
                            
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
RealtimeDropMonitor = DirectoryWatcher
EDRFileDropMonitor = DirectoryWatcher


class SandboxIngestionEngine:
    """Ingests and correlates dynamic sandbox execution captures (CAPE / Cuckoo).
    
    Supports:
    1. Static visual screenshots and OCR credential scanning across image formats.
    2. Dynamic execution telemetry parsing (Cuckoo/CAPE `report.json` process trees,
       validated IP/domain network IOCs, dropped files, and triggered signatures).
    3. Multi-report aggregation and artifact SHA-256 cross-correlation.
    """

    @staticmethod
    def parse_cuckoo_report(report_json_path: str) -> Dict[str, Any]:
        """Parse raw Cuckoo / CAPE dynamic analysis telemetry JSON report.

        Extracts process tree, dropped file IOCs, network communication IOCs (validated IP vs domain),
        and high-severity dynamic signatures.
        """
        import ipaddress
        import json
        telemetry: Dict[str, Any] = {
            "is_cuckoo_report": False,
            "report_path": report_json_path,
            "cuckoo_score": 0.0,
            "target_file": None,
            "process_tree": [],
            "network_iocs": {"ips": [], "domains": []},
            "dropped_files": [],
            "triggered_signatures": [],
            "threat_verdict": "CLEAN",
        }
        if not os.path.exists(report_json_path):
            return telemetry

        try:
            with open(report_json_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            if not isinstance(data, dict) or ("info" not in data and "behavior" not in data and "signatures" not in data):
                return telemetry

            telemetry["is_cuckoo_report"] = True

            # 1. Info & Score
            info = data.get("info", {})
            if isinstance(info, dict):
                score = float(info.get("score", 0.0))
                telemetry["cuckoo_score"] = score
                if "target" in data and isinstance(data["target"], dict):
                    telemetry["target_file"] = data["target"].get("file", {}).get("name")

            # 2. Behavior / Process tree
            behavior = data.get("behavior", {})
            if isinstance(behavior, dict):
                processes = behavior.get("processes", [])
                for p in processes:
                    if isinstance(p, dict):
                        telemetry["process_tree"].append({
                            "pid": p.get("process_id"),
                            "parent_id": p.get("parent_id"),
                            "process_name": p.get("process_name"),
                            "command_line": p.get("command_line"),
                        })

            # 3. Network IOCs with strict IP vs Domain validation
            network = data.get("network", {})
            if isinstance(network, dict):
                hosts = network.get("hosts", [])
                for h in hosts:
                    raw_host = h.get("ip") if isinstance(h, dict) else (h if isinstance(h, str) else "")
                    if raw_host:
                        try:
                            ipaddress.ip_address(raw_host)
                            if raw_host not in telemetry["network_iocs"]["ips"]:
                                telemetry["network_iocs"]["ips"].append(raw_host)
                        except ValueError:
                            # Not an IP address -> classify as domain/hostname
                            if raw_host not in telemetry["network_iocs"]["domains"]:
                                telemetry["network_iocs"]["domains"].append(raw_host)

                domains = network.get("domains", [])
                for d in domains:
                    dom_str = d.get("domain") if isinstance(d, dict) else (d if isinstance(d, str) else "")
                    if dom_str and dom_str not in telemetry["network_iocs"]["domains"]:
                        telemetry["network_iocs"]["domains"].append(dom_str)

            # 4. Dropped Files
            dropped = data.get("dropped", [])
            if isinstance(dropped, list):
                for df in dropped:
                    if isinstance(df, dict):
                        telemetry["dropped_files"].append({
                            "name": df.get("name"),
                            "sha256": df.get("sha256"),
                            "size": df.get("size"),
                        })

            # 5. Triggered Signatures
            sigs = data.get("signatures", [])
            if isinstance(sigs, list):
                for s in sigs:
                    if isinstance(s, dict):
                        severity = s.get("severity", 1)
                        telemetry["triggered_signatures"].append({
                            "name": s.get("name"),
                            "description": s.get("description"),
                            "severity": severity,
                        })

            # Verdict calculation
            score = telemetry["cuckoo_score"]
            high_sev_sigs = [s for s in telemetry["triggered_signatures"] if s.get("severity", 0) >= 3]
            if score >= 7.0 or len(high_sev_sigs) >= 2:
                telemetry["threat_verdict"] = "MALICIOUS"
            elif score >= 3.5 or len(telemetry["triggered_signatures"]) > 0:
                telemetry["threat_verdict"] = "SUSPICIOUS"
            else:
                telemetry["threat_verdict"] = "CLEAN"

        except Exception as e:
            logger.error(f"Error parsing Cuckoo report {report_json_path}: {e}")

        return telemetry

    @staticmethod
    def analyze_sandbox_artifacts(sandbox_dir: str) -> Dict[str, Any]:
        """Analyze screenshots, memory artifacts, and Cuckoo/CAPE telemetry reports with cross-correlation."""
        from lensint.core.analyzer import ImageAnalyzer
        findings: Dict[str, Any] = {
            "sandbox_dir": sandbox_dir,
            "screenshots_analyzed": 0,
            "failed_ingestions": 0,
            "high_risk_captures": [],
            "extracted_credentials": [],
            "malware_signatures": [],
            "cuckoo_telemetry": None,
            "all_cuckoo_reports": [],
            "correlated_artifacts": [],
            "overall_sandbox_verdict": "CLEAN",
        }

        if not os.path.exists(sandbox_dir):
            return findings

        supported_exts = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".tiff"}
        highest_score = 0.0
        elevated_artifact_count = 0
        analyzed_hashes: Dict[str, str] = {}  # sha256 -> relative path

        for root, _, files in os.walk(sandbox_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, sandbox_dir)

                # Check for Cuckoo JSON report(s)
                if file.lower() in ("report.json", "cuckoo.json") or (ext == ".json" and "report" in file.lower()):
                    try:
                        cuckoo_res = SandboxIngestionEngine.parse_cuckoo_report(full_path)
                        if cuckoo_res.get("is_cuckoo_report"):
                            findings["all_cuckoo_reports"].append(cuckoo_res)
                            # Keep primary telemetry (highest score or latest)
                            if findings["cuckoo_telemetry"] is None or cuckoo_res["cuckoo_score"] > findings["cuckoo_telemetry"]["cuckoo_score"]:
                                findings["cuckoo_telemetry"] = cuckoo_res

                            if cuckoo_res.get("threat_verdict") == "MALICIOUS":
                                highest_score = max(highest_score, 85.0)
                            elif cuckoo_res.get("threat_verdict") == "SUSPICIOUS":
                                highest_score = max(highest_score, 50.0)
                    except Exception as e:
                        logger.error(f"Failed to ingest Cuckoo report {rel_path}: {e}")

                if ext in supported_exts:
                    try:
                        res = ImageAnalyzer(full_path, use_cache=False).analyze()
                        findings["screenshots_analyzed"] += 1
                        if res.integrity and res.integrity.sha256:
                            analyzed_hashes[res.integrity.sha256] = rel_path

                        if res.overall_risk_score > highest_score:
                            highest_score = res.overall_risk_score

                        if res.overall_risk_level in ("HIGH", "CRITICAL"):
                            elevated_artifact_count += 1
                            findings["high_risk_captures"].append({
                                "file": rel_path,
                                "risk_score": res.overall_risk_score,
                                "findings": res.summary_findings[:3],
                            })
                        elif res.overall_risk_level == "ELEVATED":
                            elevated_artifact_count += 1

                        # Collect OCR secret findings from sandbox screens
                        if res.ocr and res.ocr.sensitive_findings:
                            for sf in res.ocr.sensitive_findings:
                                findings["extracted_credentials"].append(f"{rel_path}: {sf['type']} ({sf['redacted']})")

                        # Collect malware signatures
                        if res.malware and res.malware.threat_signatures:
                            findings["malware_signatures"].extend(res.malware.threat_signatures)
                    except Exception as e:
                        logger.error(f"Failed to ingest sandbox artifact {rel_path}: {e}")
                        findings["failed_ingestions"] += 1

        # Correlate dropped files with analyzed artifacts by cryptographic SHA-256
        for rep in findings["all_cuckoo_reports"]:
            for df in rep.get("dropped_files", []):
                df_hash = df.get("sha256")
                if df_hash and df_hash in analyzed_hashes:
                    findings["correlated_artifacts"].append({
                        "file": analyzed_hashes[df_hash],
                        "dropped_name": df.get("name"),
                        "sha256": df_hash,
                        "cuckoo_report": rep.get("report_path"),
                    })

        # Composite multi-evidence verdict
        if highest_score >= 70.0 or elevated_artifact_count >= 2:
            findings["overall_sandbox_verdict"] = "MALICIOUS"
        elif highest_score >= 35.0 or elevated_artifact_count >= 1 or len(findings["extracted_credentials"]) > 0:
            findings["overall_sandbox_verdict"] = "SUSPICIOUS"

        return findings
