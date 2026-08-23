# Forensic Chain of Custody & Tamper-Evident Audit Trails

## Courtroom Admissibility & Evidence Integrity

In digital forensics investigations, presenting evidence requires establishing an unbroken **Chain of Custody** (ISO/IEC 27037 compliant). LENSINT features a built-in cryptographic audit subsystem (`lensint/audit.py`) that ensures:

1. **Evidence Provenance**:
   - Exact UTC timestamp of analysis.
   - Case ID, Evidence Item ID, and Examiner Name.
   - Comprehensive multi-algorithm hash fingerprinting (MD5, SHA-1, SHA-256, SHA-512).
2. **Analysis Immutability**:
   - Canonical JSON representation of findings and verdicts.
   - **SHA-256 Cryptographic Seal** computed over the entire record.
3. **Tamper Detection**:
   - Any post-facto modification to an audit record immediately invalidates the cryptographic seal.

---

## Audit Record Schema

```json
{
  "version": "1.0",
  "audit_timestamp_utc": "2026-08-23T03:00:00.000000+00:00",
  "framework_version": "2.5.0",
  "chain_of_custody": {
    "case_id": "CASE-2026-0042",
    "examiner": "ForensicAnalyst_44",
    "investigation_notes": "Suspected stego exfiltration item"
  },
  "evidence_item": {
    "target_path": "/evidence/item_01.jpg",
    "file_name": "item_01.jpg",
    "file_size_bytes": 1048576,
    "detected_format": "JPEG",
    "detected_mime": "image/jpeg",
    "hashes": {
      "md5": "...",
      "sha1": "...",
      "sha256": "...",
      "sha512": "..."
    }
  },
  "forensic_verdict": {
    "risk_level": "CRITICAL",
    "risk_score": 85.0,
    "ai_verdict": "CONFIRMED_AI",
    "tampering_suspicion": "HIGH",
    "stego_detected": true,
    "malware_threats": true,
    "key_findings": [
      "Hidden trailing payload found appended past image EOF.",
      "YARA Rule match confirmed threat: WebShell_Generic_PHP_Eval."
    ]
  },
  "audit_seal_sha256": "a3b8e91c7f04..."
}
```

---

## Verifying an Audit Seal Programmatically

```python
from lensint.audit import ForensicAuditLogger

# Read record dictionary from audit log
is_valid = ForensicAuditLogger.verify_audit_record(audit_record_dict)
print(f"Evidence integrity verified: {is_valid}")
```
