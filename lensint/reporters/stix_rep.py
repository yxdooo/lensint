"""STIX 2.1 output reporter for LENSINT forensics results.

Generates a STIX 2.1 JSON Bundle containing:
- File SCO (Observed data object representing the image)
- Indicator SDOs for discovered IOCs (IPs, URLs, domains, crypto wallets)
- Malware / Tool SDOs if high-risk threats/polyglots are detected
- Note SDOs for key forensic findings
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from lensint.core.models import AnalysisResult


def render_stix_report(result: AnalysisResult, indent: int = 2) -> str:
    """Render AnalysisResult as a valid STIX 2.1 JSON Bundle string."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects: List[Dict[str, Any]] = []

    # 1. File SCO
    file_hashes: Dict[str, str] = {}
    if result.integrity.sha256:
        file_hashes["SHA-256"] = result.integrity.sha256
    if result.integrity.sha1:
        file_hashes["SHA-1"] = result.integrity.sha1
    if result.integrity.md5:
        file_hashes["MD5"] = result.integrity.md5

    file_sco_id = f"file--{uuid.uuid5(uuid.NAMESPACE_DNS, result.integrity.sha256 or result.integrity.file_name or 'lensint-file')}"
    file_sco: Dict[str, Any] = {
        "type": "file",
        "spec_version": "2.1",
        "id": file_sco_id,
        "name": result.integrity.file_name or os.path.basename(result.target_path),
        "size": result.integrity.file_size_bytes,
        "hashes": file_hashes,
    }
    if result.integrity.detected_mime:
        file_sco["mime_type"] = result.integrity.detected_mime
    objects.append(file_sco)

    # 2. Indicators for IOCs
    iocs = result.strings.iocs_detected
    for ip in iocs.get("ipv4", []):
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "name": f"Embedded IPv4 Address: {ip}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "indicator_types": ["malicious-activity", "anomalous-activity"],
        })

    for url in iocs.get("urls", []):
        escaped_url = url.replace("'", "\\'")
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "name": f"Embedded URL Endpoint: {url}",
            "pattern": f"[url:value = '{escaped_url}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "indicator_types": ["malicious-activity"],
        })

    for dom in iocs.get("domains", []):
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "name": f"Embedded Domain: {dom}",
            "pattern": f"[domain-name:value = '{dom}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "indicator_types": ["anomalous-activity"],
        })

    # 3. Malware SDO if threats detected
    if result.malware.has_threats:
        malware_id = f"malware--{uuid.uuid4()}"
        malware_sdo = {
            "type": "malware",
            "spec_version": "2.1",
            "id": malware_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Embedded Threat in {result.integrity.file_name}",
            "is_family": False,
            "malware_types": ["webshell", "dropper"] if result.malware.webshell_detected else ["unknown"],
            "description": f"Threat signatures identified: {', '.join(result.malware.threat_signatures)}",
        }
        objects.append(malware_sdo)

        # Relationship linking file to malware
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "relationship_type": "delivers",
            "source_ref": file_sco_id,
            "target_ref": malware_id,
        })

    # 4. Note SDO for forensic findings
    if result.summary_findings:
        objects.append({
            "type": "note",
            "spec_version": "2.1",
            "id": f"note--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "abstract": f"Lensint Forensics Summary (Risk: {result.overall_risk_level}, Score: {result.overall_risk_score}/100)",
            "content": "\n".join(f"- {f}" for f in result.summary_findings),
            "object_refs": [file_sco_id],
        })

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
    return json.dumps(bundle, indent=indent, ensure_ascii=False)


def export_stix_report(result: AnalysisResult, output_path: str, indent: int = 2) -> str:
    """Export STIX 2.1 bundle to a JSON file at output_path."""
    abs_path = os.path.abspath(output_path)
    parent = os.path.dirname(abs_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(render_stix_report(result, indent=indent))
    return abs_path
