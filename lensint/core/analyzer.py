from datetime import datetime, timezone
import os
from typing import Optional

from lensint.core.models import AnalysisResult
from lensint.modules.integrity import analyze_integrity
from lensint.modules.metadata import analyze_metadata
from lensint.modules.stego import analyze_stego
from lensint.modules.strings_scan import analyze_strings
from lensint.modules.tampering import analyze_tampering
from lensint.modules.ai_detect import analyze_ai_generation
from lensint.modules.malware_rules import analyze_malware_and_polyglots
from lensint.modules.threat_intel import generate_threat_intel_links, reverse_geocode
from lensint.utils.image_ops import load_image_safe


class ImageAnalyzer:
    def __init__(
        self,
        file_path: str,
        ela_quality: int = 90,
        min_string_len: int = 4,
        generate_visuals: bool = True,
        perform_geolookup: bool = False,
    ):
        self.file_path = os.path.abspath(file_path)
        self.ela_quality = ela_quality
        self.min_string_len = min_string_len
        self.generate_visuals = generate_visuals
        self.perform_geolookup = perform_geolookup

    def analyze(self) -> AnalysisResult:
        result = AnalysisResult()
        result.target_path = self.file_path
        result.timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        pil_img, raw_bytes, load_err = load_image_safe(self.file_path)
        if raw_bytes is None:
            err_msg = load_err if load_err else 'Unable to access target file.'
            result.summary_findings.append(f'Fatal read error: {err_msg}')
            result.overall_risk_score = 100.0
            result.overall_risk_level = 'CRITICAL'
            return result

        result.integrity = analyze_integrity(self.file_path, raw_bytes, pil_img)
        result.metadata = analyze_metadata(raw_bytes, pil_img)

        if self.perform_geolookup and result.metadata.gps_info:
            lat = result.metadata.gps_info['latitude']
            lon = result.metadata.gps_info['longitude']
            result.metadata.reverse_geocode = reverse_geocode(lat, lon)

        result.tampering = analyze_tampering(pil_img, ela_quality=self.ela_quality, generate_visuals=self.generate_visuals)
        result.stego = analyze_stego(raw_bytes, pil_img, generate_visuals=self.generate_visuals)
        result.strings = analyze_strings(raw_bytes, min_len=self.min_string_len)
        result.ai_detection = analyze_ai_generation(raw_bytes, pil_img, generate_visuals=self.generate_visuals)
        result.malware = analyze_malware_and_polyglots(raw_bytes)

        result.threat_intel = generate_threat_intel_links(
            sha256_hash=result.integrity.sha256,
            ips=result.strings.iocs_detected['ipv4'],
            domains=result.strings.iocs_detected['urls'],
            urls=result.strings.iocs_detected['urls'],
        )

        self._calculate_verdict(result)
        return result

    def _calculate_verdict(self, result: AnalysisResult) -> None:
        score = 0.0
        findings = []

        if result.malware.has_threats:
            score += 50.0
            for tf in result.malware.findings: findings.append(tf)

        if result.integrity.extension_mismatch:
            score += 40.0
            findings.append('Disguised file format / Extension spoofing detected.')

        if result.integrity.is_corrupt_or_truncated:
            score += 15.0
            findings.append('Image structure is damaged or truncated.')

        if result.stego.has_overlay_data:
            score += 35.0
            findings.append(f'Hidden trailing payload ({result.stego.overlay_size_bytes} bytes) found appended past image EOF.')

        suspicious_sigs = [s for s in result.stego.embedded_signatures if s['offset'] > 0]
        if suspicious_sigs:
            score += 35.0
            sig_names = ', '.join(list(set(s['signature'] for s in suspicious_sigs[:3])))
            findings.append(f'Embedded payload/archive signatures discovered: {sig_names}.')

        if result.stego.extracted_payload_type:
            score += 35.0
            findings.append(f'Carrier extraction: {result.stego.extracted_payload_type}.')

        if result.stego.lsb_stego_detected:
            score += 25.0
            findings.append('Abnormally high LSB entropy indicates active steganographic carrier.')

        if result.tampering.copy_move_detected:
            score += 35.0
            findings.append(f'Copy-Move forgery detected ({result.tampering.copy_move_match_count} cloned keypoints).')
        elif result.tampering.suspicion_level == 'HIGH':
            score += 25.0
            findings.append('High tampering probability (ELA disparity & noise variance).')
        elif result.tampering.suspicion_level == 'MEDIUM':
            score += 10.0
            findings.append('Moderate compression variance suggests localized editing.')

        if result.ai_detection.ai_verdict == 'CONFIRMED_AI':
            findings.append(f'AI Generated / Synthetic image confirmed ({result.ai_detection.ai_generator_name}).')
        elif result.ai_detection.ai_verdict == 'HIGH_PROBABILITY_AI':
            findings.append('AI Generation suspected (Characteristic diffusion FFT spectral grid spikes).')

        if result.metadata.software_footprint_findings:
            score += 10.0
            findings.append(f'Metadata confirms editing: {result.metadata.software_footprint_findings[0]}')

        if result.strings.iocs_detected['shell_commands']:
            score += 35.0
            cmds = ', '.join(result.strings.iocs_detected['shell_commands'][:3])
            findings.append(f'Dangerous shell execution keywords detected: {cmds}.')

        b64_count = len(result.strings.iocs_detected['base64_blobs'])
        if b64_count > 0:
            score += 10.0
            findings.append(f'{b64_count} encoded Base64 payload blob(s) discovered.')

        result.overall_risk_score = round(min(100.0, score), 1)
        if result.overall_risk_score >= 70.0 or result.malware.has_threats:
            result.overall_risk_level = 'CRITICAL'
        elif result.overall_risk_score >= 45.0:
            result.overall_risk_level = 'HIGH'
        elif result.overall_risk_score >= 25.0:
            result.overall_risk_level = 'ELEVATED'
        elif result.overall_risk_score > 0.0:
            result.overall_risk_level = 'LOW'
        else:
            result.overall_risk_level = 'CLEAN'

        if not findings:
            findings.append('No security threats, hidden payloads, or tampering indicators detected.')

        result.summary_findings = findings
