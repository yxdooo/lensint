import html
import json
import os
from typing import Optional
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
    ipv4_html = "".join(f"<span class='ioc-tag ioc-ip'>{_e(ip)}</span>" for ip in iocs["ipv4"]) or "<span class='dim'>None</span>"
    urls_html = "".join(f"<span class='ioc-tag ioc-url'>{_e(u)}</span>" for u in iocs["urls"]) or "<span class='dim'>None</span>"
    emails_html = "".join(f"<span class='ioc-tag ioc-email'>{_e(e)}</span>" for e in iocs["emails"]) or "<span class='dim'>None</span>"
    shells_html = "".join(f"<span class='ioc-tag ioc-shell'>{_e(s)}</span>" for s in iocs["shell_commands"]) or "<span class='dim'>None</span>"
    wallets_html = "".join(f"<span class='ioc-tag ioc-wallet'>{_e(w)}</span>" for w in iocs["crypto_wallets"]) or "<span class='dim'>None</span>"

    ela_img = f"<img src='{result.tampering.ela_b64_image}' class='preview-img' />" if result.tampering.ela_b64_image else "<div class='no-img'>N/A</div>"
    ghost_img = f"<img src='{result.tampering.jpeg_ghost_b64_image}' class='preview-img' />" if result.tampering.jpeg_ghost_b64_image else ""
    fft_img = f"<img src='{result.ai_detection.fft_b64_image}' class='preview-img' />" if result.ai_detection.fft_b64_image else "<div class='no-img'>N/A</div>"
    cm_img = f"<img src='{result.tampering.copy_move_b64_image}' class='preview-img' />" if result.tampering.copy_move_b64_image else "<div class='no-img'>No Cloning Detected</div>"
    splice_img = f"<img src='{result.tampering.splice_b64_image}' class='preview-img' />" if getattr(result.tampering, 'splice_b64_image', None) else ""

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
        geo_html = f"<tr><td class='key-cell'>Physical Address</td><td class='val-cell'>{geo_name}</td></tr>"

    dqt_desc = result.tampering.dqt_identified_encoder or "Standard Non-JPEG / Custom Tables"
    duration = getattr(result, 'analysis_duration_seconds', 0.0)
    cache_note = " &middot; Loaded from cache" if getattr(result, 'cache_hit', False) else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lensint Forensics Report - {result.integrity.file_name}</title>
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
.container {{ max-width: 1200px; margin: 0 auto; }}
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
  font-size: 16px;
  font-weight: 700;
  color: var(--accent-cyan);
  margin-bottom: 14px;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 8px;
}}
.grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
.table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.table td {{ padding: 8px 10px; border-bottom: 1px solid var(--border-color); }}
.key-cell {{ color: var(--text-muted); width: 35%; font-weight: 600; }}
.val-cell {{ color: #fff; word-break: break-all; }}
.preview-img {{ max-width: 100%; border-radius: 8px; border: 1px solid var(--border-color); }}
.no-img {{ background: var(--bg-secondary); border-radius: 8px; padding: 40px; text-align: center; color: var(--text-muted); }}
.btn-intel {{ display: inline-block; padding: 6px 12px; margin: 4px; background: #1e293b; color: var(--accent-cyan); text-decoration: none; border-radius: 6px; font-size: 12px; border: 1px solid var(--border-color); }}
.btn-intel:hover {{ background: #262f40; border-color: var(--accent-cyan); }}
.ioc-tag {{ display: inline-block; padding: 3px 8px; margin: 2px; border-radius: 4px; font-size: 12px; font-family: monospace; }}
.ioc-ip {{ background: rgba(79, 172, 254, 0.15); color: #4facfe; }}
.ioc-url {{ background: rgba(0, 242, 254, 0.15); color: #00f2fe; }}
.ioc-email {{ background: rgba(168, 85, 247, 0.15); color: #c084fc; }}
.ioc-shell {{ background: rgba(255, 51, 102, 0.2); color: #ff3366; }}
.ioc-wallet {{ background: rgba(246, 173, 85, 0.15); color: #f6ad55; }}
.font-mono {{ font-family: monospace; font-size: 12px; }}
.findings-list {{ list-style-type: disc; margin-left: 20px; line-height: 1.6; font-size: 14px; }}
.findings-list li {{ margin-bottom: 6px; color: #cbd5e1; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="title">LENSINT <span>FORENSICS</span> v2.0</div>
      <div class="subtitle">Target: {_e(result.target_path)} | Generated: {result.timestamp}</div>
    </div>
    <div class="badge {badge_class}">{result.overall_risk_level} (Score: {result.overall_risk_score}/100)</div>
  </div>

  <div class="card">
    <div class="card-title">Key Forensic Findings & Verdict Summary</div>
    <ul class="findings-list">{findings_html}</ul>
  </div>

  <div class="grid-2">
    <div class="card">
      <div class="card-title">1. File Integrity & Hashes</div>
      <table class="table">
        <tr><td class="key-cell">File Name</td><td class="val-cell">{result.integrity.file_name}</td></tr>
        <tr><td class="key-cell">Size</td><td class="val-cell">{result.integrity.file_size_human} ({result.integrity.file_size_bytes} bytes)</td></tr>
        <tr><td class="key-cell">MIME Type</td><td class="val-cell">{result.integrity.detected_mime}</td></tr>
        <tr><td class="key-cell">Extension Match</td><td class="val-cell">{'MISMATCH / SPOOFED' if result.integrity.extension_mismatch else 'Verified'}</td></tr>
        <tr><td class="key-cell">SHA-256</td><td class="val-cell font-mono">{result.integrity.sha256}</td></tr>
        <tr><td class="key-cell">MD5</td><td class="val-cell font-mono">{result.integrity.md5}</td></tr>
      </table>
    </div>

    <div class="card">
      <div class="card-title">2. Metadata & Geolocation</div>
      <table class="table">
        <tr><td class="key-cell">Camera</td><td class="val-cell">{_e(result.metadata.camera_make or 'N/A')} {_e(result.metadata.camera_model or '')}</td></tr>
        <tr><td class="key-cell">Software</td><td class="val-cell">{_e(result.metadata.software or 'N/A')}</td></tr>
        <tr><td class="key-cell">Original Date</td><td class="val-cell">{_e(result.metadata.datetime_original or 'N/A')}</td></tr>
        <tr><td class="key-cell">GPS Coordinates</td><td class="val-cell">{_e(result.metadata.gps_info['latitude']) if result.metadata.gps_info else 'N/A'}, {_e(result.metadata.gps_info['longitude']) if result.metadata.gps_info else 'N/A'}</td></tr>
        <tr><td class="key-cell">Social Provenance</td><td class="val-cell">{_e(result.metadata.social_media_provenance or 'None / Direct Device')}</td></tr>
        <tr><td class="key-cell">EXIF Thumbnail SSIM</td><td class="val-cell">{'MISMATCH (' + str(result.metadata.thumbnail_ssim_score) + ')' if result.metadata.thumbnail_mismatch_detected else 'Verified Match' if result.metadata.thumbnail_extracted else 'No embedded thumbnail'}</td></tr>
        {geo_html}
      </table>
    </div>
  </div>

  <div class="grid-2">
    <div class="card">
      <div class="card-title">3. AI / Synthetic Detection &amp; 2D FFT Spectrum</div>
      <table class="table" style="margin-bottom: 12px;">
        <tr><td class="key-cell">AI Verdict</td><td class="val-cell"><b>{_e(result.ai_detection.ai_verdict)}</b> (Score: {result.ai_detection.ai_probability_score}/100)</td></tr>
        <tr><td class="key-cell">AI Generator</td><td class="val-cell">{_e(result.ai_detection.ai_generator_name or 'None')}</td></tr>
        <tr><td class="key-cell">GAN Fingerprint</td><td class="val-cell">{'DETECTED (Score: ' + str(round(getattr(result.ai_detection, 'gan_fingerprint_score', 0))) + ')' if getattr(result.ai_detection, 'gan_fingerprint_detected', False) else 'Not detected'}</td></tr>
        <tr><td class="key-cell">PRNU Sensor Noise</td><td class="val-cell">{'Present (Score: ' + str(result.ai_detection.prnu_sensor_score) + '/100)' if getattr(result.ai_detection, 'prnu_sensor_noise_detected', False) else 'Absent / Low (' + str(getattr(result.ai_detection, 'prnu_sensor_score', 0.0)) + '/100)'}</td></tr>
        <tr><td class="key-cell">Inpainting Anomaly</td><td class="val-cell">{'DETECTED (' + str(getattr(result.ai_detection, 'inpainting_anomaly_score', 0.0)) + '/100)' if getattr(result.ai_detection, 'inpainting_anomaly_score', 0.0) > 50 else 'Uniform'}</td></tr>
        <tr><td class="key-cell">C2PA Credentials</td><td class="val-cell">{_e(', '.join(result.ai_detection.c2pa_markers)) if result.ai_detection.c2pa_present else 'None'}</td></tr>
        <tr><td class="key-cell">2D FFT Spectral Score</td><td class="val-cell">{result.ai_detection.fft_spectral_score}/100.0 (Peak Ratio: {result.ai_detection.fft_peak_ratio})</td></tr>
      </table>
      {fft_img}
    </div>

    <div class="card">
      <div class="card-title">4. Courtroom-Grade Tampering & Forgery Forensics</div>
      <table class="table" style="margin-bottom: 12px;">
        <tr><td class="key-cell">ELA Disparity Score</td><td class="val-cell">{result.tampering.ela_suspicion_score}/100.0 (Suspicion: {result.tampering.suspicion_level})</td></tr>
        <tr><td class="key-cell">Copy-Move Cloning</td><td class="val-cell">{'DETECTED' if result.tampering.copy_move_detected else 'Clean'} ({result.tampering.copy_move_match_count} pairs)</td></tr>
        <tr><td class="key-cell">JPEG Ghosts (Double Comp)</td><td class="val-cell">{'DETECTED (Qualities: ' + str(result.tampering.jpeg_ghost_qualities) + ')' if result.tampering.jpeg_ghosts_detected else 'Single Compression Uniformity'}</td></tr>
        <tr><td class="key-cell">DQT Table Signature</td><td class="val-cell">{dqt_desc}</td></tr>
        <tr><td class="key-cell">CFA Bayer Demosaicing</td><td class="val-cell">{'ANOMALY (' + str(result.tampering.cfa_inconsistency_score) + '/100)' if result.tampering.cfa_tampering_detected else str(result.tampering.cfa_inconsistency_score) + '/100 (Natural Grid)'}</td></tr>
        <tr><td class="key-cell">8x8 DCT Block Grid Phase</td><td class="val-cell">{'SHIFTED (Offset: ' + str(result.tampering.block_grid_offset) + ')' if result.tampering.block_grid_shifted else 'Aligned (0,0)'}</td></tr>
        <tr><td class="key-cell">Chromatic Aberration Vector</td><td class="val-cell">{'MISMATCH (' + str(result.tampering.chromatic_aberration_inconsistency) + '/100)' if result.tampering.chromatic_aberration_detected else str(result.tampering.chromatic_aberration_inconsistency) + '/100 (Radial Convergence)'}</td></tr>
        <tr><td class="key-cell">Median Filter / Smoothing</td><td class="val-cell">{'DETECTED (' + str(result.tampering.median_filter_score) + '/100)' if result.tampering.median_filter_detected else 'Unsmoothed'}</td></tr>
        <tr><td class="key-cell">Splice Detection</td><td class="val-cell">{'DETECTED (' + str(round(getattr(result.tampering, 'splice_confidence', 0))) + '% conf)' if getattr(result.tampering, 'splice_detected', False) else 'No splice artifacts'}</td></tr>
        <tr><td class="key-cell">Illumination Direction</td><td class="val-cell">{'CONFLICT (' + str(result.tampering.illumination_variance_score) + '/100)' if result.tampering.illumination_conflict_detected else 'Coherent Light Angle'}</td></tr>
      </table>
      {ghost_img or splice_img or cm_img or ela_img}
    </div>
  </div>

  <div class="grid-2">
    <div class="card">
      <div class="card-title">5. Steganography & Malware Rules</div>
      <table class="table">
        <tr><td class="key-cell">Appended Overlay</td><td class="val-cell">{'DETECTED (' + str(result.stego.overlay_size_bytes) + ' bytes)' if result.stego.has_overlay_data else 'Clean'}</td></tr>
        <tr><td class="key-cell">Malware / WebShells</td><td class="val-cell">{'CRITICAL: Threat Signatures Found' if result.malware.has_threats else 'Clean'}</td></tr>
        <tr><td class="key-cell">YARA Rule Hits</td><td class="val-cell">{_e(', '.join(m['rule'] for m in getattr(result.malware, 'yara_matches', []))) if getattr(result.malware, 'yara_matches', []) else 'None'}</td></tr>
        <tr><td class="key-cell">Deobfuscated Payloads</td><td class="val-cell">{str(len(getattr(result.malware, 'deobfuscated_payloads', []))) + ' extracted' if getattr(result.malware, 'deobfuscated_payloads', []) else 'None'}</td></tr>
        <tr><td class="key-cell">RS Steganalysis</td><td class="val-cell">{'DETECTED (' + str(int(getattr(result.stego, 'rs_estimated_embedding_rate', 0)*100)) + '% capacity)' if getattr(result.stego, 'rs_steganalysis_detected', False) else 'Natural LSB'}</td></tr>
        <tr><td class="key-cell">Stego Tool Signatures</td><td class="val-cell">{_e(', '.join(getattr(result.stego, 'stego_tool_signatures', []))) if getattr(result.stego, 'stego_tool_signatures', []) else 'None'}</td></tr>
        <tr><td class="key-cell">Packed/Encrypted Payload</td><td class="val-cell">{'DETECTED (' + str(len(getattr(result.malware, 'high_entropy_sections', []))) + ' section(s))' if getattr(result.malware, 'packed_payload_detected', False) else 'None'}</td></tr>
        <tr><td class="key-cell">LSB Shannon Entropy</td><td class="val-cell">{result.stego.lsb_entropy.get('Average', 0.0)}/8.0</td></tr>
      </table>
    </div>

    <div class="card">
      <div class="card-title">6. OSINT & Threat Intel Query Links</div>
      <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 10px;">Direct queries against global threat intelligence and reverse image search providers:</p>
      <div>{intel_links_html}</div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Extracted IOCs & Strings</div>
    <table class="table">
      <tr><td class="key-cell">IPv4 Addresses</td><td class="val-cell">{ipv4_html}</td></tr>
      <tr><td class="key-cell">URLs & Endpoints</td><td class="val-cell">{urls_html}</td></tr>
      <tr><td class="key-cell">Email Addresses</td><td class="val-cell">{emails_html}</td></tr>
      <tr><td class="key-cell">Shell Keywords</td><td class="val-cell">{shells_html}</td></tr>
      <tr><td class="key-cell">Crypto Wallets</td><td class="val-cell">{wallets_html}</td></tr>
    </table>
  </div>

  <div style="text-align:center; color: var(--text-muted); font-size:12px; margin-top:20px;">
    Analysis completed in {duration:.2f}s{cache_note}
  </div>
</div>
</body>
</html>"""
    return html


def export_html_report(result: AnalysisResult, output_path: str) -> None:
    content = render_html_report(result)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
