"""MISP (Malware Information Sharing Platform) JSON Event Generator for LENSINT.

Exports analysis artifacts, hashes, indicators of compromise, and tampering verdicts
into standardized MISP format.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict
from lensint.core.models import AnalysisResult


def render_misp_report(result: AnalysisResult, event_info: str = "LENSINT Image Forensics & Malware Investigation") -> str:
    """Render analysis result as a standardized MISP JSON event."""
    event_uuid = str(uuid.uuid4())
    curr_time = int(time.time())

    attributes = []

    # 1. File attributes (Hashes, filename, size)
    attributes.append({
        "uuid": str(uuid.uuid4()),
        "type": "filename",
        "category": "Payload delivery",
        "value": result.integrity.file_name or "evidence.img",
        "to_ids": False,
        "comment": "Examined image file name",
    })
    attributes.append({
        "uuid": str(uuid.uuid4()),
        "type": "sha256",
        "category": "Payload delivery",
        "value": result.integrity.sha256,
        "to_ids": True,
        "comment": "SHA-256 evidence cryptographic hash",
    })
    attributes.append({
        "uuid": str(uuid.uuid4()),
        "type": "md5",
        "category": "Payload delivery",
        "value": result.integrity.md5,
        "to_ids": True,
        "comment": "MD5 evidence hash",
    })
    attributes.append({
        "uuid": str(uuid.uuid4()),
        "type": "sha1",
        "category": "Payload delivery",
        "value": result.integrity.sha1,
        "to_ids": True,
        "comment": "SHA-1 evidence hash",
    })

    # 2. Network IOCs
    for ip in result.strings.iocs_detected.get("ipv4", []):
        attributes.append({
            "uuid": str(uuid.uuid4()),
            "type": "ip-dst",
            "category": "Network activity",
            "value": ip,
            "to_ids": True,
            "comment": "IP address extracted from carrier string analysis",
        })

    for domain in result.strings.iocs_detected.get("domains", []):
        attributes.append({
            "uuid": str(uuid.uuid4()),
            "type": "domain",
            "category": "Network activity",
            "value": domain,
            "to_ids": True,
            "comment": "Domain name extracted from image payload",
        })

    for url in result.strings.iocs_detected.get("urls", []):
        attributes.append({
            "uuid": str(uuid.uuid4()),
            "type": "url",
            "category": "Network activity",
            "value": url,
            "to_ids": True,
            "comment": "URL extracted from image payload",
        })

    # 3. YARA & Malware Threats
    for yara_hit in result.malware.yara_matches:
        attributes.append({
            "uuid": str(uuid.uuid4()),
            "type": "yara",
            "category": "Artifacts dropped",
            "value": yara_hit.get("rule", ""),
            "to_ids": False,
            "comment": f"Matched YARA rule: {yara_hit.get('description', '')}",
        })

    # 4. Forensics findings as comments/text
    for finding in result.summary_findings[:10]:
        attributes.append({
            "uuid": str(uuid.uuid4()),
            "type": "comment",
            "category": "Internal reference",
            "value": finding,
            "to_ids": False,
            "comment": "LENSINT Forensic Finding",
        })

    # Threat level ID: 1 = High, 2 = Medium, 3 = Low, 4 = Undefined
    threat_level_id = 4
    if result.overall_risk_level == "CRITICAL":
        threat_level_id = 1
    elif result.overall_risk_level in ("HIGH", "ELEVATED"):
        threat_level_id = 2
    elif result.overall_risk_level == "LOW":
        threat_level_id = 3

    misp_event = {
        "Event": {
            "uuid": event_uuid,
            "info": f"{event_info} - {result.integrity.file_name} [{result.overall_risk_level}]",
            "date": time.strftime("%Y-%m-%d"),
            "threat_level_id": str(threat_level_id),
            "analysis": "2",  # Completed
            "distribution": "1",  # Community only
            "timestamp": str(curr_time),
            "Attribute": attributes,
            "Tag": [
                {"name": "tlp:amber", "colour": "#ffc000"},
                {"name": f"lensint:risk={result.overall_risk_level.lower()}", "colour": "#d9534f" if result.overall_risk_level == "CRITICAL" else "#5cb85c"},
                {"name": "misp-galaxy:threat-actor", "colour": "#337ab7"},
            ]
        }
    }

    return json.dumps(misp_event, indent=2, ensure_ascii=False)
