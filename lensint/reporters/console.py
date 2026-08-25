"""
LENSINT - Rich Console Terminal Reporter
"""

import sys
from typing import Optional
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lensint.core.models import AnalysisResult


def render_console_report(result: AnalysisResult, console: Optional[Console] = None, quiet: bool = False) -> None:
    if console is None:
        console = Console()

    risk_colors = {
        "CLEAN": "bold green",
        "LOW": "bold cyan",
        "ELEVATED": "bold yellow",
        "HIGH": "bold red",
        "CRITICAL": "bold white on red",
    }
    verdict_color = risk_colors.get(result.overall_risk_level, "bold white")

    banner_text = Text()
    banner_text.append("LENSINT // IMAGE FORENSICS & THREAT INTELLIGENCE FRAMEWORK v2.0\n", style="bold cyan")
    banner_text.append(f"Target: {result.target_path} | Analyzed at: {result.timestamp}", style="dim")
    console.print(Panel(banner_text, box=box.ROUNDED, border_style="cyan"))

    if not quiet:
        # 1. Integrity
        t_int = Table(title="[bold]1. File Structure & Cryptographic Integrity[/bold]", box=box.SIMPLE_HEAVY, show_header=True)
        t_int.add_column("Property", style="bold white", width=24)
        t_int.add_column("Observed Value", style="cyan")
        t_int.add_row("File Name", result.integrity.file_name)
        t_int.add_row("File Size", f"{result.integrity.file_size_human} ({result.integrity.file_size_bytes} bytes)")
        t_int.add_row("Detected Format", f"{result.integrity.detected_format} ({result.integrity.detected_mime})")
        t_int.add_row("Extension Status", "[bold red]MISMATCH / SPOOFED[/bold red]" if result.integrity.extension_mismatch else "[green]Verified Match[/green]")
        if result.integrity.dimensions:
            w, h = result.integrity.dimensions
            t_int.add_row("Dimensions", f"{w} x {h} pixels (Mode: {result.integrity.color_mode})")
        t_int.add_row("SHA-256", result.integrity.sha256)
        console.print(t_int)

        # 2. Metadata & Geocoding
        t_meta = Table(title="[bold]2. Metadata, Geolocation & Footprints[/bold]", box=box.SIMPLE_HEAVY, show_header=True)
        t_meta.add_column("Attribute", style="bold white", width=24)
        t_meta.add_column("Value / Details", style="cyan")
        t_meta.add_row("EXIF Header", "[green]Present[/green]" if result.metadata.exif_present else "[dim]Not Found[/dim]")
        cam_info = (result.metadata.camera_make or "") + " " + (result.metadata.camera_model or "N/A")
        t_meta.add_row("Camera Make / Model", cam_info.strip())
        t_meta.add_row("Software Stamp", result.metadata.software or "N/A")
        t_meta.add_row("Original Timestamp", result.metadata.datetime_original or "N/A")
        if result.metadata.gps_info:
            gps = result.metadata.gps_info
            lat, lon, dms = gps["latitude"], gps["longitude"], gps["dms"]
            t_meta.add_row("GPS Coordinates", f"{lat}, {lon} ({dms})")
            if result.metadata.reverse_geocode:
                t_meta.add_row("Physical Location", result.metadata.reverse_geocode.get("display_name", "N/A")[:90])
            t_meta.add_row("Map Link", gps["google_maps_url"])
        else:
            t_meta.add_row("GPS Geolocation", "[dim]No GPS tags found[/dim]")
        if result.metadata.social_media_provenance:
            t_meta.add_row("Social Provenance", f"[yellow]{result.metadata.social_media_provenance}[/yellow]")
        if result.metadata.thumbnail_extracted:
            ssim_str = f"[bold red]MISMATCH (SSIM: {result.metadata.thumbnail_ssim_score})[/bold red]" if result.metadata.thumbnail_mismatch_detected else f"[green]Verified (SSIM: {result.metadata.thumbnail_ssim_score})[/green]"
            t_meta.add_row("EXIF Thumbnail SSIM", ssim_str)
        console.print(t_meta)

        # 3. AI Generation & Deepfake Detection
        t_ai = Table(title="[bold]3. AI Generation & Deepfake Detection[/bold]", box=box.SIMPLE_HEAVY, show_header=True)
        t_ai.add_column("AI Detection Layer", style="bold white", width=24)
        t_ai.add_column("Assessment", style="cyan")
        ai_col = "bold red" if result.ai_detection.is_ai_generated else "green"
        t_ai.add_row("AI Verdict", f"[{ai_col}]{result.ai_detection.ai_verdict} (Score: {result.ai_detection.ai_probability_score}/100)[/{ai_col}]")
        t_ai.add_row("Generator Fingerprint", result.ai_detection.ai_generator_name or "None Detected")
        c2pa_str = ", ".join(result.ai_detection.c2pa_markers) if result.ai_detection.c2pa_present else "None Detected"
        t_ai.add_row("C2PA Content Credentials", c2pa_str)
        t_ai.add_row("2D FFT Spectral Score", f"{result.ai_detection.fft_spectral_score}/100.0 (Peak Ratio: {result.ai_detection.fft_peak_ratio})")
        prnu_str = f"[green]Present (Score: {result.ai_detection.prnu_sensor_score}/100)[/green]" if result.ai_detection.prnu_sensor_noise_detected else f"[bold yellow]Absent / Low ({result.ai_detection.prnu_sensor_score}/100)[/bold yellow]"
        t_ai.add_row("PRNU Hardware Sensor", prnu_str)
        console.print(t_ai)

        # 4. Forensic Deep Tampering Forensics
        t_tamp = Table(title="[bold]4. Forensic Tampering & Manipulation Analysis[/bold]", box=box.SIMPLE_HEAVY, show_header=True)
        t_tamp.add_column("Forensic Method", style="bold white", width=26)
        t_tamp.add_column("Observation / Measurement", style="cyan")
        t_tamp.add_row("Error Level Analysis (ELA)", f"{result.tampering.ela_suspicion_score} / 100.0 (Confidence: {result.tampering.ela_confidence:.0f}%)")

        if result.tampering.splice_detected:
            t_tamp.add_row("Splice (Noise Map)", f"[bold red]DETECTED ({result.tampering.splice_confidence:.0f}% conf)[/bold red]")
        else:
            t_tamp.add_row("Splice (Noise Map)", "[green]Uniform Sensor Noise[/green]")

        cm_val = f"[bold red]DETECTED ({result.tampering.copy_move_match_count} pairs)[/bold red]" if result.tampering.copy_move_detected else "[green]Clean (No duplicate clusters)[/green]"
        t_tamp.add_row("Copy-Move Cloning", cm_val)

        ghost_val = f"[bold red]DETECTED (Qualities: {result.tampering.jpeg_ghost_qualities})[/bold red]" if result.tampering.jpeg_ghosts_detected else "[green]Single Compression Uniformity[/green]"
        t_tamp.add_row("JPEG Ghosts (Double Comp)", ghost_val)

        dqt_val = f"{result.tampering.dqt_identified_encoder} (Est. Q: {result.tampering.dqt_quality_estimate}%)" if result.tampering.dqt_found and result.tampering.dqt_identified_encoder else "[dim]Not a standard JPEG DQT[/dim]"
        t_tamp.add_row("DQT Quantization Signature", dqt_val)

        cfa_val = f"[bold red]ANOMALY ({result.tampering.cfa_inconsistency_score}/100)[/bold red]" if result.tampering.cfa_tampering_detected else f"{result.tampering.cfa_inconsistency_score}/100 ([green]Natural Bayer Grid[/green])"
        t_tamp.add_row("CFA Demosaicing Residual", cfa_val)

        grid_val = f"[bold red]SHIFT DETECTED (Offset: {result.tampering.block_grid_offset})[/bold red]" if result.tampering.block_grid_shifted else f"Aligned (0,0) (Score: {result.tampering.block_artifact_score}/100)"
        t_tamp.add_row("8x8 DCT Block Grid Phase", grid_val)

        ca_val = f"[bold red]OPTICAL MISMATCH ({result.tampering.chromatic_aberration_inconsistency}/100)[/bold red]" if result.tampering.chromatic_aberration_detected else f"{result.tampering.chromatic_aberration_inconsistency}/100 ([green]Radial Convergence[/green])"
        t_tamp.add_row("Chromatic Aberration Vector", ca_val)

        mf_val = f"[bold red]DETECTED ({result.tampering.median_filter_score}/100)[/bold red]" if result.tampering.median_filter_detected else f"{result.tampering.median_filter_score}/100 ([green]Unsmoothed[/green])"
        t_tamp.add_row("Median Filter / Smoothing", mf_val)

        illum_val = f"[bold red]LIGHTING CONFLICT ({result.tampering.illumination_variance_score}/100)[/bold red]" if result.tampering.illumination_conflict_detected else f"{result.tampering.illumination_variance_score}/100 ([green]Coherent Light Source[/green])"
        t_tamp.add_row("Illumination Vector Angle", illum_val)

        t_tamp.add_row("Sensor Noise Inconsistency", f"{result.tampering.noise_inconsistency_score} / 100.0")
        console.print(t_tamp)

        # 5. Stego & Malware
        t_stego = Table(title="[bold]5. Steganography & Malware Indicators[/bold]", box=box.SIMPLE_HEAVY, show_header=True)
        t_stego.add_column("Threat Layer", style="bold white", width=24)
        t_stego.add_column("Status / Findings", style="cyan")
        if result.stego.has_overlay_data:
            ov_off = hex(result.stego.overlay_offset) if result.stego.overlay_offset else "0x0"
            t_stego.add_row("Appended Overlay", f"[bold red]DETECTED ({result.stego.overlay_size_bytes} bytes at {ov_off})[/bold red]")
        else:
            t_stego.add_row("Appended Overlay", "[green]Clean[/green]")
        if result.malware.has_threats:
            thr_str = ", ".join(result.malware.polyglot_types + result.malware.threat_signatures)
            t_stego.add_row("Malware & Polyglots", f"[bold red]THREAT DETECTED: {thr_str}[/bold red]")
        else:
            t_stego.add_row("Malware & Polyglots", "[green]Clean (No webshells/polyglots)[/green]")
        if result.malware.yara_matches:
            y_rules = ", ".join(m["rule"] for m in result.malware.yara_matches)
            t_stego.add_row("YARA Rule Matches", f"[bold red]{y_rules}[/bold red]")
        if result.malware.deobfuscated_payloads:
            t_stego.add_row("Deobfuscated Payloads", f"[bold red]{len(result.malware.deobfuscated_payloads)} extracted payload(s)[/bold red]")
        if result.stego.rs_steganalysis_detected:
            t_stego.add_row("RS Steganalysis", f"[bold red]DETECTED ({int(result.stego.rs_estimated_embedding_rate*100)}% capacity)[/bold red]")
        if result.stego.stego_tool_signatures:
            t_stego.add_row("Stego Tool Imprint", ", ".join(result.stego.stego_tool_signatures))
        if result.stego.lsb_entropy:
            ent = result.stego.lsb_entropy.get("Average", 0.0)
            t_stego.add_row("LSB Shannon Entropy", f"{ent}/8.0 ([bold red]Stego Alert[/bold red])" if result.stego.lsb_stego_detected else f"{ent}/8.0 (Normal)")
        console.print(t_stego)

        # 6. Strings & IOCs
        t_str = Table(title="[bold]6. String Extraction & Threat Intel Lookups[/bold]", box=box.SIMPLE_HEAVY, show_header=True)
        t_str.add_column("Indicator", style="bold white", width=24)
        t_str.add_column("Observed Values", style="cyan")
        iocs = result.strings.iocs_detected
        t_str.add_row("Total Strings Extracted", str(result.strings.total_strings_found))
        t_str.add_row("IPv4 Addresses", ", ".join(iocs["ipv4"]) if iocs["ipv4"] else "[dim]None[/dim]")
        t_str.add_row("URLs & Onion", ", ".join(iocs["urls"][:3]) if iocs["urls"] else "[dim]None[/dim]")
        shells_str = ", ".join(iocs["shell_commands"])
        t_str.add_row("Shell Execution Keywords", f"[bold red]{shells_str}[/bold red]" if shells_str else "[dim]None[/dim]")
        t_str.add_row("VirusTotal Intel Link", result.threat_intel.virustotal_file_url or "N/A")
        console.print(t_str)

    # Verdict
    lines = []
    lines.append(f"Overall Risk Score: [{verdict_color}]{result.overall_risk_score} / 100.0[/{verdict_color}] | Risk Level: [{verdict_color}]{result.overall_risk_level}[/{verdict_color}]\n")
    lines.append("[bold]Key Forensic Findings:[/bold]")
    for f in result.summary_findings:
        lines.append(f" - {f}")

    console.print(Panel("\n".join(lines), title="[bold]FORENSIC VERDICT & THREAT SUMMARY[/bold]", box=box.DOUBLE, border_style=verdict_color.split()[-1] if " " in verdict_color else verdict_color.replace("bold ", "")))
