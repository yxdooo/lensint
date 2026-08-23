"""Forensic Chain of Custody & Audit Trail Module for LENSINT.

Generates cryptographically sealed, tamper-evident audit records for every
forensic analysis run, ensuring courtroom admissibility and compliance with
ISO/IEC 27037 digital evidence handling standards using chained hash validation.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lensint.config import config
from lensint.core.models import AnalysisResult

logger = logging.getLogger("lensint.audit")


def _generate_record_seal(record: Dict[str, Any]) -> str:
    """Generate SHA-256 seal for an audit record payload."""
    canonical_json = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class ForensicAuditLogger:
    """Manages structured, immutable audit log records for forensic investigations."""

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or config.audit_log_dir
        if config.audit_log_enabled:
            try:
                self.log_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.warning(f"Could not create audit directory {self.log_dir}: {e}")

    def _get_last_record_seal(self, target_file: Path) -> str:
        """Read the last record seal from the target audit ledger for hash chaining."""
        if not target_file.exists() or target_file.stat().st_size == 0:
            return "0" * 64  # Genesis block hash

        try:
            with open(target_file, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                if lines:
                    last_record = json.loads(lines[-1])
                    return last_record.get("audit_seal_sha256", "0" * 64)
        except Exception:
            pass
        return "0" * 64

    def record_analysis(
        self,
        result: AnalysisResult,
        case_id: Optional[str] = None,
        examiner: Optional[str] = None,
        notes: Optional[str] = None,
        custom_log_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record an analysis run to the tamper-evident audit log with chained seal."""
        now_utc = datetime.now(timezone.utc).isoformat()
        case_id = case_id or "UNASSIGNED"
        examiner = examiner or os.getenv("USERNAME") or os.getenv("USER") or "LENSINT_ANALYST"

        if custom_log_path:
            target_file = Path(custom_log_path)
        else:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            target_file = self.log_dir / f"lensint_audit_{date_str}.jsonl"

        prev_seal = self._get_last_record_seal(target_file)

        audit_entry: Dict[str, Any] = {
            "version": "2.0",
            "audit_timestamp_utc": now_utc,
            "framework_version": "3.5.0",
            "previous_record_seal": prev_seal,
            "chain_of_custody": {
                "case_id": case_id,
                "examiner": examiner,
                "investigation_notes": notes or "",
            },
            "evidence_item": {
                "target_path": str(result.target_path),
                "file_name": result.integrity.file_name,
                "file_size_bytes": result.integrity.file_size_bytes,
                "detected_format": result.integrity.detected_format,
                "detected_mime": result.integrity.detected_mime,
                "hashes": {
                    "md5": result.integrity.md5,
                    "sha1": result.integrity.sha1,
                    "sha256": result.integrity.sha256,
                    "sha512": result.integrity.sha512,
                },
            },
            "forensic_verdict": {
                "risk_level": result.overall_risk_level,
                "risk_score": result.overall_risk_score,
                "ai_verdict": result.ai_detection.ai_verdict,
                "tampering_suspicion": result.tampering.suspicion_level,
                "stego_detected": result.stego.has_overlay_data or result.stego.lsb_stego_detected or getattr(result.stego, 'rs_steganalysis_detected', False),
                "malware_threats": result.malware.has_threats,
                "key_findings": result.summary_findings,
            },
            "execution_metadata": {
                "analysis_duration_seconds": round(result.analysis_duration_seconds, 4),
                "cache_hit": result.cache_hit,
            },
        }

        # Cryptographically seal the audit record with chained dependency
        record_seal = _generate_record_seal(audit_entry)
        audit_entry["audit_seal_sha256"] = record_seal

        if config.audit_log_enabled or custom_log_path:
            self._write_log(audit_entry, target_file)

        return audit_entry

    def _write_log(self, entry: Dict[str, Any], target_file: Path) -> None:
        """Append audit entry to JSONL ledger."""
        try:
            target_file.parent.mkdir(parents=True, exist_ok=True)
            with open(target_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write forensic audit record: {e}")

    @staticmethod
    def verify_audit_record(record: Dict[str, Any]) -> bool:
        """Verify the cryptographic integrity of an individual sealed audit record."""
        if "audit_seal_sha256" not in record:
            return False
        expected_seal = record["audit_seal_sha256"]
        record_copy = {k: v for k, v in record.items() if k != "audit_seal_sha256"}
        computed_seal = _generate_record_seal(record_copy)
        return expected_seal == computed_seal

    @classmethod
    def verify_audit_chain(cls, log_path: str) -> Tuple[bool, int, Optional[str]]:
        """Verify the entire sequential hash chain in an audit log file.

        Returns (is_valid, record_count, error_message).
        """
        path = Path(log_path)
        if not path.exists():
            return False, 0, f"Audit log file not found: {log_path}"

        records = []
        with open(path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append((line_no, json.loads(line)))
                except json.JSONDecodeError:
                    return False, len(records), f"Corrupted JSON syntax on line {line_no}"

        if not records:
            return True, 0, None

        expected_prev_seal = "0" * 64
        for idx, (line_no, rec) in enumerate(records):
            # 1. Verify self-seal
            if not cls.verify_audit_record(rec):
                return False, len(records), f"Seal mismatch on record line {line_no}"

            # 2. Verify hash chain link (if version 2.0 with chaining)
            if rec.get("version") == "2.0":
                actual_prev = rec.get("previous_record_seal")
                if actual_prev != expected_prev_seal:
                    return False, len(records), f"Chain break on line {line_no}: expected prev seal {expected_prev_seal}, got {actual_prev}"
                expected_prev_seal = rec.get("audit_seal_sha256", "")

        return True, len(records), None


# Global audit logger
audit_logger = ForensicAuditLogger()
