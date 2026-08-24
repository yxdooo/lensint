# Cryptographic Chain of Custody, Audit Ledger, and Legal Admissibility

## Overview

In digital forensics and incident response (DFIR), evidence must withstand rigorous legal scrutiny in court proceedings. Presenting digital evidence requires establishing an unbroken, tamper-evident **Chain of Custody** compliant with **ISO/IEC 27037:2012** (*Information technology — Security techniques — Guidelines for identification, collection, acquisition and preservation of digital evidence*), the **Federal Rules of Evidence (FRE 702 / FRE 901)**, and the **Daubert Standard**.

LENSINT implements a cryptographic audit ledger subsystem (`lensint.audit`) and an RFC 3161 Trusted Timestamping Protocol (TSP) client (`lensint.utils.tsa`) to mathematically guarantee evidence provenance, examiner accountability, and analysis immutability.

---

## Legal Admissibility Framework

### 1. ISO/IEC 27037:2012 Digital Evidence Handling
LENSINT enforces the four core principles of ISO/IEC 27037:
- **Auditability**: Every analysis step, threshold applied, algorithm executed, and parameter configured is immutably documented.
- **Repeatability**: Independent examiners running LENSINT against the identical evidence item obtain verifiable, identical mathematical results.
- **Reproducibility**: Analysis conducted across different hardware platforms yields identical hash digests and analytical metrics.
- **Justifiability**: All risk scoring and tampering verdicts are derived from transparent, literature-backed mathematical models rather than opaque heuristics.

### 2. Federal Rules of Evidence (FRE 702 & 901)
- **FRE 702 (Testimony by Expert Witnesses)**: The analysis relies on sufficient facts and reliable scientific principles. LENSINT PDF reports disclose empirical error rates, academic dataset baselines, and peer-reviewed citations.
- **FRE 901 (Authenticating or Identifying Evidence)**: Demonstrates that the evidence presented is what the proponent claims. LENSINT computes multi-hash cryptographic fingerprints (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `SSDEEP`, `Meta PDQ`) at the point of ingestion to prove byte-level integrity.

### 3. Daubert Standard Criteria
In accordance with *Daubert v. Merrell Dow Pharmaceuticals, Inc.* (509 U.S. 579), LENSINT discloses:
1. **Empirical Testability**: Every analytical detector is evaluated on standard public benchmarks (CASIA v2.0, CoMoFoD, BOSSBase 1.01, ForenSynths).
2. **Known or Potential Error Rates**: Explicit True Positive Rate (TPR), False Positive Rate (FPR), ROC-AUC, and 95% Confidence Intervals are incorporated into formal expert reports.
3. **Peer-Reviewed Scientific Foundations**: Methodologies are cited to IEEE TIFS, CVPR, and ACM publications.
4. **General Acceptance**: Algorithms adhere to established digital forensic standards (PRNU sensor noise, 2D-DCT quantization analysis, Westfeld $\chi^2$ steganalysis).

---

## Sequential Cryptographic Hash Chaining

The LENSINT audit logger records all operations to append-only JSONL files (`~/.lensint/audit/lensint_audit_YYYY-MM-DD.jsonl`). To prevent retroactive record modification, insertion, or deletion, each audit entry incorporates a sequential cryptographic hash chain.

### Mathematical Chaining Model

Let $\mathbf{R}_k$ be the $k$-th forensic audit record payload, and $S_k$ be its corresponding SHA-256 audit seal.
- **Genesis Block ($k = 0$)**: The previous record seal is defined as 64 zero hex digits:
  $$S_0 = 0^{64}$$
- **Iterative Chaining ($k \ge 1$)**: The seal of record $k$ is computed by serializing the record with its link to $S_{k-1}$ into canonical deterministic JSON (sorted keys, compact separators):
  $$\mathbf{R}_k' = \mathbf{R}_k \cup \{\text{"previous\_record\_seal"}: S_{k-1}\}$$
  $$S_k = \text{SHA-256}\left( \text{CanonicalJSON}\left( \mathbf{R}_k' \right) \right)$$
  $$\text{Final Record } \mathbf{E}_k = \mathbf{R}_k' \cup \{\text{"audit\_seal\_sha256"}: S_k\}$$

If an adversary modifies a single bit in record $j$, its seal $S_j$ changes, causing an immediate verification failure at record $j+1$ ($S_{j} \neq \mathbf{R}_{j+1}.\text{previous\_record\_seal}$), invalidating the entire subsequent audit chain.

---

## Audit Record Schema Specification

```json
{
  "version": "2.0",
  "audit_timestamp_utc": "2026-08-24T00:22:15.120450+00:00",
  "framework_version": "3.6.0",
  "previous_record_seal": "8f3b2a1c0d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
  "chain_of_custody": {
    "case_id": "CASE-2026-CRIM-4402",
    "examiner": "Dr. Jane Doe, Ph.D.",
    "investigation_notes": "Suspected steganographic payload delivery in forensic triage"
  },
  "evidence_item": {
    "target_path": "/evidence/evidence_item.jpg",
    "file_name": "evidence_item.jpg",
    "file_size_bytes": 1048576,
    "detected_format": "JPEG",
    "detected_mime": "image/jpeg",
    "hashes": {
      "md5": "c4ca4238a0b923820dcc509a6f75849b",
      "sha1": "356a192b7913b04c54574d18c28d46e6395428ab",
      "sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
      "sha512": "36f56388221257b774b171449bdd01b205570d8fbf19ebb9d1000826b2a408b8b5564fb3b38914d19f73429db152c90f00b932239c4f31f8a4fb356ca0ec9e0e"
    }
  },
  "forensic_verdict": {
    "risk_level": "CRITICAL",
    "risk_score": 92.5,
    "ai_verdict": "HUMAN_NATURAL_PHOTOGRAPH",
    "tampering_suspicion": "HIGH",
    "stego_detected": true,
    "malware_threats": true,
    "key_findings": [
      "Hidden trailing payload (4520 bytes) found appended past image EOF.",
      "YARA Rule match confirmed threat: WebShell_Generic_PHP_Eval."
    ]
  },
  "execution_metadata": {
    "analysis_duration_seconds": 0.4215,
    "cache_hit": false
  },
  "audit_seal_sha256": "4a1d9c7e3f2b8a0d6c5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c"
}
```

---

## RFC 3161 Trusted Timestamping Protocol (TSP) Integration

To provide non-repudiation and prove that evidence existed in a specific cryptographic state prior to a certain date, LENSINT queries accredited Time-Stamp Authorities (TSAs).

### Binary Protocol Interaction
1. **ASN.1 DER Request Formulation**:
   LENSINT constructs a binary `TimeStampReq` structure containing the SHA-256 hash of the evidence:
   ```
   TimeStampReq ::= SEQUENCE {
      version           INTEGER { v1(1) },
      messageImprint    MessageImprint {
         hashAlgorithm  AlgorithmIdentifier (id-sha256: 2.16.840.1.101.3.4.2.1),
         hashedMessage  OCTET STRING (32 bytes)
      },
      certReq           BOOLEAN TRUE
   }
   ```
2. **HTTP Transmission**:
   The binary request is transmitted via HTTP POST with `Content-Type: application/timestamp-query` to an accredited TSA endpoint (e.g., FreeTSA, DigiCert, Sectigo).
3. **Response Parsing and Verification**:
   The TSA returns a `TimeStampResp` ASN.1 structure. LENSINT validates `PKIStatusInfo == 0` (Granted), extracts the cryptographic `GeneralizedTime` (tag `0x18`), and records the Base64-encoded token for courtroom exhibit verification.
4. **Air-Gapped Local Cryptographic Time-Seal**:
   In isolated, classified, or air-gapped forensic environments where external network routing is disabled, LENSINT computes a local cryptographic SHA-256 seal combining UTC system time, local monotonic counters, and the evidence digest.

---

## Programmatic Audit Verification API

Accredited forensic auditors and opposing expert witnesses can verify the mathematical integrity of individual records or entire audit ledger files using the built-in verification APIs.

```python
from pathlib import Path
from lensint.audit import ForensicAuditLogger

# 1. Verify Individual Sealed Audit Record
sample_record = {
    "version": "2.0",
    "audit_timestamp_utc": "2026-08-24T00:22:15.120450+00:00",
    "previous_record_seal": "0000000000000000000000000000000000000000000000000000000000000000",
    # ... remaining record fields ...
    "audit_seal_sha256": "4a1d9c7e3f2b8a0d6c5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c"
}

is_record_valid = ForensicAuditLogger.verify_audit_record(sample_record)
print(f"Record Seal Integrity: {'VALID' if is_record_valid else 'COMPROMISED'}")

# 2. Verify Entire Sequential Hash Chain in JSONL Ledger
audit_log_path = Path.home() / ".lensint" / "audit" / "lensint_audit_2026-08-24.jsonl"
is_chain_valid, record_count, error_msg = ForensicAuditLogger.verify_audit_chain(str(audit_log_path))

if is_chain_valid:
    print(f"Audit Ledger Verification PASSED: {record_count} unbroken records verified.")
else:
    print(f"Audit Ledger Verification FAILED: {error_msg}")
```
