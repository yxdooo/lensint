"""
LENSINT - Advanced Image Forensics, AI Detection & Threat Intelligence Tool
Command Line Interface (CLI) Definition.
"""

import argparse
import glob
import os
import sys
from typing import List

from rich.console import Console

from lensint import __version__
from lensint.core.analyzer import ImageAnalyzer
from lensint.reporters.console import render_console_report
from lensint.reporters.html_rep import render_html_report
from lensint.reporters.json_rep import render_json_report


def build_serve_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lensint serve", description="Start Lensint REST API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lensint",
        description="LENSINT // High-Precision Digital Image Forensics, AI Detection & Threat Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  lensint target.jpg
  lensint target.png --html report.html --json report.json
  lensint samples_dir/ --batch --quiet
  lensint suspicious.jpg --geo-lookup
  lensint stego_carrier.png --extract-overlay dumped_payload.bin
  lensint serve --port 8000
        """,
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"lensint v{__version__}",
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Path to target image file or directory for batch analysis (or 'serve')",
    )
    parser.add_argument(
        "--html",
        metavar="REPORT_PATH",
        help="Generate a standalone interactive dark-mode HTML forensic report",
    )
    parser.add_argument(
        "--json",
        metavar="REPORT_PATH",
        help="Export comprehensive forensic data to a JSON file",
    )
    parser.add_argument(
        "--stix",
        metavar="PATH",
        help="Export STIX 2.1 threat intelligence bundle to specified path",
    )
    parser.add_argument(
        "--misp",
        metavar="PATH",
        help="Export standardized MISP JSON event format to specified path",
    )
    parser.add_argument(
        "--generate-yara",
        metavar="PATH",
        help="Generate deployable YARA detection rule (.yar) matching detected threats and hashes",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable result caching (always re-analyze)",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Analyze all supported images within the target directory",
    )
    parser.add_argument(
        "--extract-overlay",
        metavar="OUT_FILE",
        help="Extract any hidden trailing overlay payload data past the image EOF",
    )
    parser.add_argument(
        "--geo-lookup",
        action="store_true",
        help="Perform reverse geocoding via OpenStreetMap Nominatim for GPS coordinates",
    )
    parser.add_argument(
        "--ela-quality",
        type=int,
        default=90,
        help="JPEG recompression quality for Error Level Analysis (default: 90)",
    )
    parser.add_argument(
        "--min-string-len",
        type=int,
        default=4,
        help="Minimum length for ASCII/UTF-16 string extraction (default: 4)",
    )
    parser.add_argument(
        "--case-id",
        metavar="ID",
        help="Forensic Case Identifier for Chain of Custody record (e.g., CASE-2026-042)",
    )
    parser.add_argument(
        "--examiner",
        metavar="NAME",
        help="Forensic Analyst / Examiner name for audit log",
    )
    parser.add_argument(
        "--audit-log",
        metavar="PATH",
        help="Custom file path to append cryptographically sealed forensic audit log entry",
    )
    parser.add_argument(
        "--no-audit",
        action="store_true",
        help="Disable forensic audit trail recording for this run",
    )
    parser.add_argument(
        "--carve-memory",
        metavar="DUMP_PATH",
        help="Carve and analyze volatile image buffers from raw RAM memory dump (.raw, .dmp, .vmem)",
    )
    parser.add_argument(
        "--watch-dir",
        metavar="DIR",
        help="Run EDR real-time monitor on target directory for newly dropped evidence files",
    )
    parser.add_argument(
        "--sandbox-dir",
        metavar="DIR",
        help="Ingest and correlate dynamic sandbox run execution artifacts (CAPE / Cuckoo)",
    )
    parser.add_argument(
        "--no-visuals",
        action="store_true",
        help="Disable generation of visual ELA/thumbnails (speeds up analysis)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress detailed console tables and output only the final verdict",
    )

    return parser


def handle_serve(args_list: List[str]) -> int:
    try:
        from lensint.server import start_server
        parser = build_serve_parser()
        args = parser.parse_args(args_list)
        console = Console()
        console.print(f"[bold cyan]Starting Lensint Forensics REST API on http://{args.host}:{args.port}...[/bold cyan]")
        start_server(host=args.host, port=args.port)
        return 0
    except ImportError as e:
        sys.stderr.write(f"Server dependencies missing: {e}\n")
        return 1


def main(args_list: List[str] = None) -> int:
    if args_list is None:
        args_list = sys.argv[1:]

    console = Console()

    if args_list and args_list[0] == "serve":
        return handle_serve(args_list[1:])

    parser = build_parser()
    args = parser.parse_args(args_list)

    # 1. Memory Dump Carving
    if args.carve_memory:
        from lensint.modules.memory_forensics import MemoryForensicsEngine
        console.print(f"[bold cyan]Scanning volatile memory dump:[/bold cyan] {args.carve_memory}...")
        engine = MemoryForensicsEngine()
        carved = engine.scan_memory_dump_file(args.carve_memory)
        console.print(f"[bold green]Successfully carved {len(carved)} image buffer(s) from memory dump.[/bold green]")
        for idx, c in enumerate(carved[:10]):
            console.print(f"  [{idx+1}] Offset: {c['offset_hex']} | Format: {c['format']} | Size: {c['size_bytes']} B | Dims: {c['dimensions']} | Source: {c['source']}")
        return 0

    # 2. Real-Time Directory Artifact Watcher
    if args.watch_dir:
        from lensint.modules.edr_sandbox import DirectoryWatcher
        console.print(f"[bold cyan]Starting Real-Time Artifact Watcher on:[/bold cyan] {args.watch_dir} (Press Ctrl+C to stop)...")
        monitor = DirectoryWatcher(
            args.watch_dir,
            alert_callback=lambda res: console.print(
                f"[bold red]CRITICAL ALERT:[/bold red] {res.integrity.file_name} -> {res.overall_risk_level} (Score: {res.overall_risk_score})"
            ),
        )
        try:
            monitor.watch_continuously(poll_interval=1.0)
        except KeyboardInterrupt:
            console.print("\n[yellow]Watcher stopped by analyst.[/yellow]")
        return 0

    # 3. Sandbox Ingestion
    if args.sandbox_dir:
        from lensint.modules.edr_sandbox import SandboxIngestionEngine
        console.print(f"[bold cyan]Ingesting dynamic sandbox run artifacts:[/bold cyan] {args.sandbox_dir}...")
        findings = SandboxIngestionEngine.analyze_sandbox_artifacts(args.sandbox_dir)
        console.print(f"[bold green]Sandbox Analysis Verdict:[/bold green] {findings['overall_sandbox_verdict']} (Analyzed {findings['screenshots_analyzed']} capture(s))")
        if findings["extracted_credentials"]:
            console.print(f"[bold red]Extracted Credentials ({len(findings['extracted_credentials'])}):[/bold red]")
            for cred in findings["extracted_credentials"][:5]:
                console.print(f"  • {cred}")
        return 0

    if not args.target:
        parser.print_help()
        return 0

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        console.print(f"[bold red]Error:[/bold red] Target path does not exist: {target}", file=sys.stderr)
        return 1

    targets: List[str] = []
    if os.path.isdir(target):
        if not args.batch:
            console.print("[yellow]Notice:[/yellow] Target is a directory. Automatically enabling --batch mode.")
        exts = ["*.jpg", "*.jpeg", "*.png", "*.gif", "*.webp", "*.bmp", "*.tiff", "*.tif"]
        for ext in exts:
            targets.extend(glob.glob(os.path.join(target, ext)))
            targets.extend(glob.glob(os.path.join(target, ext.upper())))
        targets = sorted(list(set(targets)))
        if not targets:
            console.print(f"[bold red]Error:[/bold red] No supported image files found in {target}", file=sys.stderr)
            return 1
    else:
        targets = [target]

    is_batch = len(targets) > 1

    def _batch_path(base_path: str, stem: str) -> str:
        """Insert <stem> before the extension of base_path when in batch mode."""
        if not is_batch:
            return base_path
        root, ext = os.path.splitext(base_path)
        return f"{root}_{stem}{ext}"

    def process_target(current_target: str) -> None:
        try:
            analyzer = ImageAnalyzer(
                file_path=current_target,
                ela_quality=args.ela_quality,
                min_string_len=args.min_string_len,
                generate_visuals=not args.no_visuals,
                perform_geolookup=args.geo_lookup,
                use_cache=not args.no_cache,
            )

            result = analyzer.analyze()
            render_console_report(result, console=console, quiet=args.quiet)

            if getattr(result, 'cache_hit', False):
                console.print(f"[dim]⚡ Result loaded from cache for {os.path.basename(current_target)}[/dim]")
            if hasattr(result, 'analysis_duration_seconds'):
                console.print(f"[dim]Analysis completed in {result.analysis_duration_seconds:.2f}s[/dim]")

            target_stem = os.path.splitext(os.path.basename(current_target))[0]

            if args.extract_overlay:
                out_overlay = _batch_path(args.extract_overlay, target_stem)
                if result.stego.has_overlay_data:
                    from lensint.modules.stego import detect_overlay_data
                    with open(current_target, "rb") as f:
                        raw_b = f.read()
                    _, _, _, ov_bytes = detect_overlay_data(raw_b)
                    if ov_bytes:
                        with open(out_overlay, "wb") as f_out:
                            f_out.write(ov_bytes)
                        console.print(f"[bold green]Successfully extracted overlay payload ({len(ov_bytes)} bytes) to:[/bold green] {out_overlay}")
                else:
                    console.print(f"[yellow]No overlay data found in {os.path.basename(current_target)}.[/yellow]")

            if args.json:
                json_path = _batch_path(args.json, target_stem)
                with open(json_path, "w", encoding="utf-8") as jf:
                    jf.write(render_json_report(result))
                console.print(f"[bold green]JSON forensic report written to:[/bold green] {json_path}")

            if args.html:
                html_path = _batch_path(args.html, target_stem)
                with open(html_path, "w", encoding="utf-8") as hf:
                    hf.write(render_html_report(result))
                console.print(f"[bold green]HTML forensic report written to:[/bold green] {html_path}")

            if args.stix:
                from lensint.reporters.stix_rep import export_stix_report
                stix_path = _batch_path(args.stix, target_stem)
                export_stix_report(result, stix_path)
                console.print(f"[bold green]STIX 2.1 threat bundle written to:[/bold green] {stix_path}")

            if args.misp:
                from lensint.reporters.misp_rep import render_misp_report
                misp_path = _batch_path(args.misp, target_stem)
                with open(misp_path, "w", encoding="utf-8") as mf:
                    mf.write(render_misp_report(result))
                console.print(f"[bold green]MISP JSON event written to:[/bold green] {misp_path}")

            if args.generate_yara:
                from lensint.reporters.yara_gen import generate_yara_rule
                yara_path = _batch_path(args.generate_yara, target_stem)
                with open(yara_path, "w", encoding="utf-8") as yf:
                    yf.write(generate_yara_rule(result))
                console.print(f"[bold green]Deployable YARA rule written to:[/bold green] {yara_path}")

            # Forensic Audit Trail & Chain of Custody Record
            if not args.no_audit:
                from lensint.audit import audit_logger
                audit_entry = audit_logger.record_analysis(
                    result=result,
                    case_id=args.case_id,
                    examiner=args.examiner,
                    custom_log_path=args.audit_log,
                )
                if args.audit_log:
                    console.print(f"[dim]🔒 Sealed audit record saved (Seal: {audit_entry['audit_seal_sha256'][:12]}...)[/dim]")
                    
        except Exception as e:
            console.print(f"[bold red]Failed to process {current_target}:[/bold red] {e}")

    if is_batch:
        from concurrent.futures import ThreadPoolExecutor
        console.print(f"[bold cyan]Starting batch analysis for {len(targets)} files...[/bold cyan]")
        with ThreadPoolExecutor(max_workers=min(32, (os.cpu_count() or 1) + 4)) as executor:
            executor.map(process_target, targets)
    else:
        for t in targets:
            process_target(t)

    return 0


if __name__ == "__main__":
    sys.exit(main())
