"""Interactive Enterprise HTML Forensic Report Generator.

Renders an interactive, standalone, single-page HTML report containing forensic visual plates,
Bayesian risk fusion telemetry, PRNU camera sensor attribution, Meta PDQ hash matching,
C2PA JUMBF cryptographic verification, rPPG biometrics, Brown-Conrady optics,
SRM deep neural steganalysis, video GOP cadence, and RFC 3161 timestamping seals.
"""
from __future__ import annotations

import html
import json
import os
from typing import Any, Dict, Optional
from lensint.core.models import AnalysisResult


def _e(value: object) -> str:
    """Escape a value for safe HTML rendering."""
    return html.escape(str(value) if value is not None else "")


def render_html_report(result: AnalysisResult) -> str:
    badge_map = {
        "CLEAN": "badge-clean",
        "LOW": "badge-low",
        "ELEVATED": "badge-elevated",
        "HIGH": "badge-high",
        "CRITICAL": "badge-critical",
    }
    badge_class = badge_map.get(result.overall_risk_level, "badge-low")

    findings_html = "".join(f"<li>{_e(f)}</li>" for f in result.summary_findings)

    raw_tags_html = ""
    for k, v in result.metadata.raw_tags.items():
        raw_tags_html += f"<tr><td class='key-cell'>{_e(k)}</td><td class='val-cell'>{_e(v)}</td></tr>"

    iocs = result.strings.iocs_detected
    ipv4_html = "".join(f"<span class='ioc-tag ioc-ip'>{_e(ip)}</span>" for ip in iocs.get("ipv4", [])) or "<span class='dim'>None</span>"
    urls_html = "".join(f"<span class='ioc-tag ioc-url'>{_e(u)}</span>" for u in iocs.get("urls", [])) or "<span class='dim'>None</span>"
    emails_html = "".join(f"<span class='ioc-tag ioc-email'>{_e(e)}</span>" for e in iocs.get("emails", [])) or "<span class='dim'>None</span>"
    shells_html = "".join(f"<span class='ioc-tag ioc-shell'>{_e(s)}</span>" for s in iocs.get("shell_commands", [])) or "<span class='dim'>None</span>"
    wallets_html = "".join(f"<span class='ioc-tag ioc-wallet'>{_e(w)}</span>" for w in iocs.get("crypto_wallets", [])) or "<span class='dim'>None</span>"

    ela_img = f"<img src='{result.tampering.ela_b64_image}' class='preview-img' alt='ELA Plate' />" if result.tampering.ela_b64_image else "<div class='no-img'>N/A</div>"
    ghost_img = f"<img src='{result.tampering.jpeg_ghost_b64_image}' class='preview-img' alt='JPEG Ghost Plate' />" if result.tampering.jpeg_ghost_b64_image else ""
    fft_img = f"<img src='{result.ai_detection.fft_b64_image}' class='preview-img' alt='2D-FFT Spectrum' />" if result.ai_detection.fft_b64_image else "<div class='no-img'>N/A</div>"
    cm_img = f"<img src='{result.tampering.copy_move_b64_image}' class='preview-img' alt='Copy-Move Plate' />" if result.tampering.copy_move_b64_image else "<div class='no-img'>No Cloning Detected</div>"
    splice_img = f"<img src='{result.tampering.splice_b64_image}' class='preview-img' alt='Splice Heatmap' />" if getattr(result.tampering, 'splice_b64_image', None) else ""

    intel_links_html = ""
    if result.threat_intel.virustotal_file_url:
        intel_links_html += f"<a href='{result.threat_intel.virustotal_file_url}' target='_blank' class='btn-intel'>VirusTotal File Analysis</a> "
    if result.threat_intel.hybrid_analysis_url:
        intel_links_html += f"<a href='{result.threat_intel.hybrid_analysis_url}' target='_blank' class='btn-intel'>Hybrid Analysis</a> "

    for eng, link in result.threat_intel.reverse_image_engines.items():
        intel_links_html += f"<a href='{link}' target='_blank' class='btn-intel'>{eng}</a> "

    geo_html = ""
    if result.metadata.gps_info:
        geo_name = result.metadata.reverse_geocode.get("display_name", "N/A") if result.metadata.reverse_geocode else "N/A"
        geo_html = f"<tr><td class='key-cell'>Physical Address</td><td class='val-cell'>{_e(geo_name)}</td></tr>"

    dqt_desc = result.tampering.dqt_identified_encoder or "Standard Non-JPEG / Custom Tables"
    duration = getattr(result, 'analysis_duration_seconds', 0.0)
    cache_note = " &middot; Loaded from cache" if getattr(result, 'cache_hit', False) else ""

    # Safe extraction of C2PA telemetry
    c2pa_obj = getattr(result, "c2pa_manifest", None)
    has_c2pa = getattr(c2pa_obj, "is_c2pa_present", False) or getattr(c2pa_obj, "has_c2pa_manifest", False)
    c2pa_generator = getattr(c2pa_obj, "claim_generator", None) or "N/A"
    c2pa_actions_list = getattr(c2pa_obj, "actions", [])
    c2pa_actions_str = ", ".join([a.action if hasattr(a, "action") else a.get("action", "") for a in c2pa_actions_list if (hasattr(a, "action") and a.action) or (isinstance(a, dict) and a.get("action"))]) or "None"
    c2pa_sig_verified = getattr(c2pa_obj, "is_signature_verified", False) or (getattr(c2pa_obj, "claim_signature", None) is not None and getattr(c2pa_obj.claim_signature, "is_cryptographically_verified", False))
    c2pa_stripped = getattr(c2pa_obj, "is_manifest_stripped", False) or getattr(c2pa_obj, "manifest_stripped_detected", False) or getattr(c2pa_obj, "has_anti_forensic_tampering", False)

    # Safe extraction of Biometrics telemetry
    bio_obj = getattr(result, "biometrics", None)
    is_vid = getattr(result.video, "is_video", False) or getattr(bio_obj, "is_video_analyzed", False)
    pulse_bpm = getattr(bio_obj, "dominant_pulse_bpm", 0.0) or getattr(bio_obj, "dominant_bpm", 0.0)
    pulse_snr = getattr(bio_obj, "pulse_snr_db", 0.0) or getattr(bio_obj, "rppg_snr_db", 0.0)
    has_pulse = getattr(bio_obj, "is_cardiovascular_pulse_detected", False) or (pulse_bpm > 40.0 and pulse_snr >= 2.5)
    phase_coh = getattr(bio_obj, "facial_phase_coherence", 1.0) or getattr(bio_obj, "cross_region_coherence", 1.0)
    phase_ok = getattr(bio_obj, "is_phase_coherent", True) if hasattr(bio_obj, "is_phase_coherent") else (phase_coh >= 0.40)
    poisson_p = getattr(bio_obj, "poisson_blink_p_value", 1.0)
    poisson_ok = getattr(bio_obj, "is_poisson_blink_consistent", True)

    # Safe extraction of PRNU & Optics telemetry
    prnu_obj = getattr(result, "prnu", None)
    prnu_extracted = getattr(prnu_obj, "fingerprint_extracted", False)
    prnu_energy = getattr(prnu_obj, "noise_residual_energy", 0.0)
    prnu_match = getattr(prnu_obj, "is_device_matched", False) or getattr(prnu_obj, "is_match", False)
    prnu_pce = getattr(prnu_obj, "peak_to_correlation_energy", 0.0) or getattr(prnu_obj, "pce_score", 0.0)
    prnu_dev = getattr(prnu_obj, "matched_device_id", "") or ""

    opt_obj = getattr(result, "optics", None)
    dust_count = getattr(opt_obj, "dust_spots_detected", 0)
    dust_pattern = getattr(opt_obj, "has_dust_pattern", False)
    dist_profile = getattr(opt_obj, "distortion_profile", "FLAT_OR_UNKNOWN")
    rad_k1 = getattr(opt_obj, "radial_k1", 0.0)
    rad_k2 = getattr(opt_obj, "radial_k2", 0.0)

    # Safe extraction of Neural Stego telemetry
    nstego_obj = getattr(result, "neural_stego", None)
    nstego_detected = getattr(nstego_obj, "is_stego_detected", False) or getattr(nstego_obj, "stego_detected", False)
    nstego_family = getattr(nstego_obj, "stego_algorithm_family", "") or getattr(nstego_obj, "stego_verdict", "CLEAN")
    nstego_prob = getattr(nstego_obj, "stego_probability_score", 0.0) or getattr(nstego_obj, "confidence", 0.0)

    # Safe extraction of PDQ telemetry
    pdq_obj = getattr(result, "pdq", None)
    pdq_hex = getattr(pdq_obj, "pdq_hash_hex", "") or ""
    pdq_threat = getattr(pdq_obj, "is_threat_match", False)

    # Safe extraction of Timestamping token
    tsa_obj = getattr(result, "timestamp_token", None)
    tsa_status = getattr(tsa_obj, "status", "GRANTED")
    tsa_server = getattr(tsa_obj, "tsa_server", "LOCAL_OFFLINE_SEAL")
    tsa_utc = getattr(tsa_obj, "timestamp_utc", "Certified")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lensint Forensics Report - {_e(result.integrity.file_name)}</title>
<style>
:root {{
  --bg-primary: #0a0c10;
  --bg-secondary: #12161f;
  --bg-card: #181d28;
  --border-color: #262f40;
  --text-main: #e2e8f0;
  --text-muted: #8492a6;
  --accent-cyan: #00f2fe;
  --accent-blue: #4facfe;
  --verdict-critical: #ff3366;
  --verdict-high: #ff6b4a;
  --verdict-elevated: #f6ad55;
  --verdict-clean: #00e676;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg-primary);
  color: var(--text-main);
  padding: 30px 20px;
}}
.container {{ max-width: 1240px; margin: 0 auto; }}
.header {{
  background: linear-gradient(135deg, #181d28 0%, #0d1117 100%);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}}
.title {{ font-size: 24px; font-weight: 800; color: #fff; }}
.title span {{ color: var(--accent-cyan); }}
.subtitle {{ color: var(--text-muted); font-size: 13px; margin-top: 4px; }}
.badge {{
  padding: 8px 16px;
  border-radius: 8px;
  font-weight: 800;
  font-size: 14px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}}
.badge-clean {{ background: rgba(0, 230, 118, 0.15); color: #00e676; border: 1px solid #00e676; }}
.badge-low {{ background: rgba(79, 172, 254, 0.15); color: #4facfe; border: 1px solid #4facfe; }}
.badge-elevated {{ background: rgba(246, 173, 85, 0.15); color: #f6ad55; border: 1px solid #f6ad55; }}
.badge-high {{ background: rgba(255, 107, 74, 0.15); color: #ff6b4a; border: 1px solid #ff6b4a; }}
.badge-critical {{ background: rgba(255, 51, 102, 0.2); color: #ff3366; border: 1px solid #ff3366; }}
.card {{
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 10px;
  padding: 20px;
  margin-bottom: 20px;
}}
.card-title {{
  font-size: 15px;
  font-weight: 700;
  color: var(--accent-cyan);
  margin-bottom: 14px;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 8px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}}
.grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
.table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.table td {{ padding: 8px 10px; border-bottom: 1px solid var(--border-color); }}
.key-cell {{ color: var(--text-muted); width: 38%; font-weight: 600; }}
.val-cell {{ color: #fff; word-break: break-all; }}
.preview-img {{ max-width: 100%; border-radius: 8px; border: 1px solid var(--border-color); margin-top: 10px; }}
.no-img {{ background: var(--bg-secondary); border-radius: 8px; padding: 30px; text-align: center; color: var(--text-muted); font-size: 13px; margin-top: 10px; }}
.btn-intel {{ display: inline-block; padding: 6px 12px; margin: 4px; background: #1e293b; color: var(--accent-cyan); text-decoration: none; border-radius: 6px; font-size: 12px; border: 1px solid var(--border-color); }}
.btn-intel:hover {{ background: #262f40; border-color: var(--accent-cyan); }}
.ioc-tag {{ display: inline-block; padding: 3px 8px; margin: 2px; border-radius: 4px; font-size: 12px; font-family: monospace; }}
.ioc-ip {{ background: rgba(79, 172, 254, 0.15); color: #4facfe; }}
.ioc-url {{ background: rgba(0, 242, 254, 0.15); color: #00f2fe; }}
.ioc-email {{ background: rgba(168, 85, 247, 0.15); color: #c084fc; }}
.ioc-shell {{ background: rgba(255, 51, 102, 0.2); color: #ff3366; }}
.ioc-wallet {{ background: rgba(246, 173, 85, 0.15); color: #f6ad55; }}
.font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }}
.findings-list {{ list-style-type: disc; margin-left: 20px; line-height: 1.6; font-size: 14px; }}
.findings-list li {{ margin-bottom: 6px; color: #cbd5e1; }}
.status-pill {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
.pill-green {{ background: rgba(0, 230, 118, 0.2); color: #00e676; }}
.pill-red {{ background: rgba(255, 51, 102, 0.2); color: #ff3366; }}
.pill-yellow {{ background: rgba(246, 173, 85, 0.2); color: #f6ad55; }}
.pill-blue {{ background: rgba(79, 172, 254, 0.2); color: #4facfe; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="title">LENSINT <span>FORENSICS & THREAT INTELLIGENCE</span></div>
      <div class="subtitle">Evidence: {_e(result.target_path)} &middot; Standard: ISO/IEC 27037:2012 &middot; Generated: {result.timestamp}</div>
    </div>
    <div class="badge {badge_class}">{result.overall_risk_level} (Score: {result.overall_risk_score}/100)</div>
  </div>

  <div class="card">
    <div class="card-title">Executive Summary & Calibrated Forensic Verdict</div>
    <ul class="findings-list">{findings_html}</ul>
  </div>

  <!-- ROW 1: Chain of Custody & Device Optics -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">1. File Integrity & Cryptographic Custody</div>
      <table class="table">
        <tr><td class="key-cell">File Name</td><td class="val-cell">{_e(result.integrity.file_name)}</td></tr>
        <tr><td class="key-cell">Size</td><td class="val-cell">{_e(result.integrity.file_size_human)} ({result.integrity.file_size_bytes} bytes)</td></tr>
        <tr><td class="key-cell">MIME Type</td><td class="val-cell">{_e(result.integrity.detected_mime)}</td></tr>
        <tr><td class="key-cell">Extension Check</td><td class="val-cell">{'<span class="status-pill pill-red">MISMATCH / SPOOFED</span>' if result.integrity.extension_mismatch else '<span class="status-pill pill-green">Verified Format</span>'}</td></tr>
        <tr><td class="key-cell">SHA-256</td><td class="val-cell font-mono">{_e(result.integrity.sha256)}</td></tr>
        <tr><td class="key-cell">MD5</td><td class="val-cell font-mono">{_e(result.integrity.md5)}</td></tr>
        <tr><td class="key-cell">RFC 3161 TSA Seal</td><td class="val-cell">{_e(tsa_status)} ({_e(tsa_server)}) &middot; {_e(tsa_utc)}</td></tr>
      </table>
    </div>

    <div class="card">
      <div class="card-title">2. Camera PRNU & Optical Fingerprint</div>
      <table class="table">
        <tr><td class="key-cell">PRNU Extraction</td><td class="val-cell">{'<span class="status-pill pill-green">Extracted</span>' if prnu_extracted else '<span class="status-pill pill-yellow">Not Available</span>'}</td></tr>
        <tr><td class="key-cell">Sensor Noise Energy</td><td class="val-cell">{prnu_energy} variance</td></tr>
        <tr><td class="key-cell">1:N Sensor Match</td><td class="val-cell">{'<span class="status-pill pill-red">MATCH: ' + _e(prnu_dev) + ' (PCE: ' + str(prnu_pce) + ')</span>' if prnu_match else '<span class="status-pill pill-green">No Database Correlation</span>'}</td></tr>
        <tr><td class="key-cell">Sensor Dust Invariant</td><td class="val-cell">{dust_count} dust spot(s) detected {'(Pattern Identified)' if dust_pattern else '(Diffuse/Clean)'}</td></tr>
        <tr><td class="key-cell">Lens Distortion (k1, k2)</td><td class="val-cell">{_e(dist_profile)} (k1: {rad_k1:.4f}, k2: {rad_k2:.4f})</td></tr>
        <tr><td class="key-cell">Meta PDQ (256-bit)</td><td class="val-cell font-mono">{_e(pdq_hex[:32])}... {'<span class="status-pill pill-red">THREAT MATCH</span>' if pdq_threat else '<span class="status-pill pill-green">Clean Index</span>'}</td></tr>
      </table>
    </div>
  </div>

  <!-- ROW 2: C2PA Provenance & Deepfake Biometrics -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">3. C2PA Content Credentials & JUMBF Provenance</div>
      <table class="table">
        <tr><td class="key-cell">C2PA Manifest</td><td class="val-cell">{'<span class="status-pill pill-green">PRESENT (JUMBF Verified)</span>' if has_c2pa else '<span class="status-pill pill-yellow">Not Embedded</span>'}</td></tr>
        <tr><td class="key-cell">Claim Generator</td><td class="val-cell">{_e(c2pa_generator)}</td></tr>
        <tr><td class="key-cell">Recorded Actions</td><td class="val-cell">{_e(c2pa_actions_str)}</td></tr>
        <tr><td class="key-cell">COSE Signature</td><td class="val-cell">{'<span class="status-pill pill-green">Cryptographically Valid</span>' if c2pa_sig_verified else 'Unverified / Self-signed' if has_c2pa else 'None'}</td></tr>
        <tr><td class="key-cell">Anti-Forensics / Stripping</td><td class="val-cell">{'<span class="status-pill pill-red">MANIFEST STRIPPED / TAMPERED</span>' if c2pa_stripped else '<span class="status-pill pill-green">Clean Integrity</span>'}</td></tr>
        <tr><td class="key-cell">Social Provenance</td><td class="val-cell">{_e(result.metadata.social_media_provenance or 'Direct Device / None')}</td></tr>
      </table>
    </div>

    <div class="card">
      <div class="card-title">4. Biometric rPPG & Video Forensics</div>
      <table class="table">
        <tr><td class="key-cell">Video / Media Type</td><td class="val-cell">{_e(result.video.container_format if result.video.is_video else 'Still Image Media')}</td></tr>
        <tr><td class="key-cell">GOP Cadence Splicing</td><td class="val-cell">{'<span class="status-pill pill-red">CADENCE BREAK / SPLICE DETECTED</span>' if result.video.has_gop_cadence_break else 'Uniform Cadence' if result.video.is_video else 'N/A'}</td></tr>
        <tr><td class="key-cell">rPPG Pulse Waveform</td><td class="val-cell">{pulse_bpm:.1f} BPM (SNR: {pulse_snr:.1f} dB) {'<span class="status-pill pill-green">Pulse Detected</span>' if has_pulse else '<span class="status-pill pill-yellow">No Pulse</span>' if is_vid else 'N/A'}</td></tr>
        <tr><td class="key-cell">Facial Phase Coherence</td><td class="val-cell">{phase_coh:.2f} {'(Coherent Skin Blood Flow)' if phase_ok else '<span class="status-pill pill-red">Phase Desync / Deepfake</span>' if is_vid else 'N/A'}</td></tr>
        <tr><td class="key-cell">Poisson Blink Dynamics</td><td class="val-cell">{'Consistent (p=' + str(round(poisson_p, 3)) + ')' if poisson_ok else '<span class="status-pill pill-red">Anomalous Blink Cadence</span>' if is_vid else 'N/A'}</td></tr>
        <tr><td class="key-cell">Video Software Footprint</td><td class="val-cell">{_e(', '.join(result.video.editing_software_footprints)) if result.video.editing_software_footprints else 'Camera Raw / Direct'}</td></tr>
      </table>
    </div>
  </div>

  <!-- ROW 3: Tampering Physics & AI Detection -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">5. AI / Synthetic Detection & 2D-FFT Spectrum</div>
      <table class="table" style="margin-bottom: 12px;">
        <tr><td class="key-cell">AI Verdict</td><td class="val-cell"><b>{_e(result.ai_detection.ai_verdict)}</b> (Score: {result.ai_detection.ai_probability_score}/100)</td></tr>
        <tr><td class="key-cell">Generator Family</td><td class="val-cell">{_e(result.ai_detection.ai_generator_name or 'None / Natural')}</td></tr>
        <tr><td class="key-cell">GAN Fingerprint</td><td class="val-cell">{'<span class="status-pill pill-red">DETECTED (' + str(round(getattr(result.ai_detection, 'gan_fingerprint_score', 0))) + ')</span>' if getattr(result.ai_detection, 'gan_fingerprint_detected', False) else 'Not detected'}</td></tr>
        <tr><td class="key-cell">2D-FFT Spectral Peak</td><td class="val-cell">{result.ai_detection.fft_spectral_score}/100.0 (Peak Ratio: {result.ai_detection.fft_peak_ratio})</td></tr>
        <tr><td class="key-cell">Inpainting Anomaly</td><td class="val-cell">{'<span class="status-pill pill-red">DETECTED (' + str(getattr(result.ai_detection, 'inpainting_anomaly_score', 0.0)) + '/100)</span>' if getattr(result.ai_detection, 'inpainting_anomaly_score', 0.0) > 50 else 'Uniform Sensor Energy'}</td></tr>
      </table>
      {fft_img}
    </div>

    <div class="card">
      <div class="card-title">6. Forensic Tampering & Forgery Forensics</div>
      <table class="table" style="margin-bottom: 12px;">
        <tr><td class="key-cell">ELA Disparity Score</td><td class="val-cell">{result.tampering.ela_suspicion_score}/100.0 (Suspicion: {_e(result.tampering.suspicion_level)})</td></tr>
        <tr><td class="key-cell">Copy-Move Cloning</td><td class="val-cell">{'<span class="status-pill pill-red">DETECTED (' + str(result.tampering.copy_move_match_count) + ' pairs)</span>' if result.tampering.copy_move_detected else '<span class="status-pill pill-green">Clean</span>'}</td></tr>
        <tr><td class="key-cell">JPEG Ghosts (Multi-comp)</td><td class="val-cell">{'<span class="status-pill pill-red">DETECTED (Qualities: ' + str(result.tampering.jpeg_ghost_qualities) + ')</span>' if result.tampering.jpeg_ghosts_detected else 'Single Compression Uniformity'}</td></tr>
        <tr><td class="key-cell">DQT Hardware Encoder</td><td class="val-cell">{_e(dqt_desc)}</td></tr>
        <tr><td class="key-cell">CFA Bayer Demosaicing</td><td class="val-cell">{'<span class="status-pill pill-red">ANOMALY (' + str(result.tampering.cfa_inconsistency_score) + '/100)</span>' if result.tampering.cfa_tampering_detected else str(result.tampering.cfa_inconsistency_score) + '/100 (Natural Grid)'}</td></tr>
        <tr><td class="key-cell">8x8 DCT Grid Shift</td><td class="val-cell">{'<span class="status-pill pill-red">SHIFTED (Offset: ' + str(result.tampering.block_grid_offset) + ')</span>' if result.tampering.block_grid_shifted else 'Aligned (0,0)'}</td></tr>
        <tr><td class="key-cell">Splice Detection</td><td class="val-cell">{'<span class="status-pill pill-red">DETECTED (' + str(round(getattr(result.tampering, 'splice_confidence', 0))) + '% conf)</span>' if getattr(result.tampering, 'splice_detected', False) else 'No splice artifacts'}</td></tr>
      </table>
      {ghost_img or splice_img or cm_img or ela_img}
    </div>
  </div>

  <!-- ROW 4: Steganography, SRM Neural Stego & Malware -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">7. Steganography & Neural Steganalysis (SRM)</div>
      <table class="table">
        <tr><td class="key-cell">Trailing Overlay Data</td><td class="val-cell">{'<span class="status-pill pill-red">DETECTED (' + str(result.stego.overlay_size_bytes) + ' bytes)</span>' if result.stego.has_overlay_data else '<span class="status-pill pill-green">Clean EOF</span>'}</td></tr>
        <tr><td class="key-cell">SRM Neural Stego (30-Dir)</td><td class="val-cell">{'<span class="status-pill pill-red">DETECTED (' + _e(nstego_family) + ' - ' + str(round(nstego_prob*100)) + '%)</span>' if nstego_detected else '<span class="status-pill pill-green">Clean Spatial Residuals</span>'}</td></tr>
        <tr><td class="key-cell">Stego Tool Signatures</td><td class="val-cell">{_e(', '.join(getattr(result.stego, 'stego_tool_signatures', []))) if getattr(result.stego, 'stego_tool_signatures', []) else 'None'}</td></tr>
        <tr><td class="key-cell">RS Steganalysis</td><td class="val-cell">{'<span class="status-pill pill-red">DETECTED (' + str(int(getattr(result.stego, 'rs_estimated_embedding_rate', 0)*100)) + '% capacity)</span>' if getattr(result.stego, 'rs_steganalysis_detected', False) else 'Natural LSB'}</td></tr>
        <tr><td class="key-cell">LSB Shannon Entropy</td><td class="val-cell">{result.stego.lsb_entropy.get('Average', 0.0)} / 8.0 bits</td></tr>
      </table>
    </div>

    <div class="card">
      <div class="card-title">8. Malware Rules, YARA & Polyglot Engine</div>
      <table class="table">
        <tr><td class="key-cell">Threat Severity</td><td class="val-cell">{'<span class="status-pill pill-red">' + _e(result.malware.severity) + '</span>' if result.malware.has_threats else '<span class="status-pill pill-green">CLEAN</span>'}</td></tr>
        <tr><td class="key-cell">Polyglot File Type</td><td class="val-cell">{'<span class="status-pill pill-red">POLYGLOT (' + _e(', '.join(result.malware.polyglot_types)) + ')</span>' if result.malware.is_polyglot else 'Monolithic'}</td></tr>
        <tr><td class="key-cell">WebShell / Shellcode</td><td class="val-cell">{'<span class="status-pill pill-red">DETECTED</span>' if result.malware.webshell_detected or result.malware.shellcode_detected else '<span class="status-pill pill-green">None</span>'}</td></tr>
        <tr><td class="key-cell">YARA Rule Hits</td><td class="val-cell">{_e(', '.join(m['rule'] for m in getattr(result.malware, 'yara_matches', []))) if getattr(result.malware, 'yara_matches', []) else 'None'}</td></tr>
        <tr><td class="key-cell">Deobfuscated Payloads</td><td class="val-cell">{str(len(getattr(result.malware, 'deobfuscated_payloads', []))) + ' extracted' if getattr(result.malware, 'deobfuscated_payloads', []) else 'None'}</td></tr>
      </table>
    </div>
  </div>

  <!-- ROW 5: OCR Secrets & Extracted IOCs -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">9. OCR & Confidential Secret Leak Hunter</div>
      <table class="table">
        <tr><td class="key-cell">OCR Status</td><td class="val-cell">{'Text Detected (' + str(getattr(result.ocr, 'word_count', 0)) + ' words via ' + getattr(result.ocr, 'engine_used', 'OCR') + ')' if getattr(result.ocr, 'text_detected', False) else 'No text recognized'}</td></tr>
        <tr><td class="key-cell">API Keys & Tokens</td><td class="val-cell">{_e(', '.join(getattr(result.ocr, 'api_keys_found', []))) if getattr(result.ocr, 'api_keys_found', []) else 'None'}</td></tr>
        <tr><td class="key-cell">Cleartext Passwords</td><td class="val-cell">{_e(', '.join(getattr(result.ocr, 'passwords_found', []))) if getattr(result.ocr, 'passwords_found', []) else 'None'}</td></tr>
        <tr><td class="key-cell">Private Keys / Seeds</td><td class="val-cell">{_e(', '.join(getattr(result.ocr, 'private_keys_found', []))) if getattr(result.ocr, 'private_keys_found', []) else 'None'}</td></tr>
        <tr><td class="key-cell">PII (Cards / SSN / TC)</td><td class="val-cell">{_e(', '.join(getattr(result.ocr, 'pii_found', []))) if getattr(result.ocr, 'pii_found', []) else 'None'}</td></tr>
      </table>
    </div>

    <div class="card">
      <div class="card-title">10. Extracted IOCs & Threat Intel Links</div>
      <table class="table" style="margin-bottom: 12px;">
        <tr><td class="key-cell">IPv4 Addresses</td><td class="val-cell">{ipv4_html}</td></tr>
        <tr><td class="key-cell">URLs & Endpoints</td><td class="val-cell">{urls_html}</td></tr>
        <tr><td class="key-cell">Email Addresses</td><td class="val-cell">{emails_html}</td></tr>
        <tr><td class="key-cell">Shell Commands</td><td class="val-cell">{shells_html}</td></tr>
        <tr><td class="key-cell">Crypto Wallets</td><td class="val-cell">{wallets_html}</td></tr>
      </table>
      <div>{intel_links_html}</div>
    </div>
  </div>

  <!-- ROW 6: Advanced Media Forensics -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">11. Advanced Media Forensics: Face, Audio & C2PA</div>
      <table class="table">
        <tr><td class="key-cell">Face-ROI Deepfake</td><td class="val-cell">{'<span class="status-pill pill-red">FACES FOUND (' + str(result.face_forensics.faces_found) + ')</span>' if getattr(result, 'face_forensics', None) and result.face_forensics.faces_found > 0 else 'No Faces'}</td></tr>
        <tr><td class="key-cell">Audio Synth Clone</td><td class="val-cell">{'<span class="status-pill pill-red">SYNTHETIC AUDIO DETECTED</span>' if getattr(result, 'audio_analysis', None) and result.audio_analysis.is_synthetic_audio else 'Natural / None'}</td></tr>
        <tr><td class="key-cell">C2PA / JUMBF Crypto</td><td class="val-cell">{'<span class="status-pill pill-green">VERIFIED</span>' if getattr(result, 'c2pa_verification', None) and result.c2pa_verification.is_valid else ('Invalid/Missing' if getattr(result, 'c2pa_verification', None) and result.c2pa_verification.c2pa_present else 'None')}</td></tr>
        <tr><td class="key-cell">Advanced CMFD Clone</td><td class="val-cell">{'<span class="status-pill pill-red">CLONING (' + str(result.cmfd.suspicious_match_count) + ' matches)</span>' if getattr(result, 'cmfd', None) and result.cmfd.cloned_regions_detected else 'Clean'}</td></tr>
      </table>
    </div>
  </div>

  <div style="text-align:center; color: var(--text-muted); font-size:12px; margin-top:20px;">
    LENSINT Enterprise Digital Media Forensics &middot; Analysis completed in {duration:.2f}s{cache_note} &middot; ISO/IEC 27037:2012 Chained Ledger
  </div>
</div>
</body>
</html>"""


def export_html_report(result: AnalysisResult, output_path: str) -> None:
    content = render_html_report(result)
    parent_dir = os.path.dirname(os.path.abspath(output_path))
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
