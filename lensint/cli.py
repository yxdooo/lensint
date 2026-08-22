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
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind (default: 0.0.0.0)")
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

    for current_target in targets:
        analyzer = ImageAnalyzer(
            file_path=current_target,
            ela_quality=args.ela_quality,
            min_string_len=args.min_string_len,
            generate_visuals=True,
            perform_geolookup=args.geo_lookup,
            use_cache=not args.no_cache,
        )

        result = analyzer.analyze()
        render_console_report(result, console=console, quiet=args.quiet)

        if getattr(result, 'cache_hit', False):
            console.print("[dim]⚡ Result loaded from cache[/dim]")
        if hasattr(result, 'analysis_duration_seconds'):
            console.print(f"[dim]Analysis completed in {result.analysis_duration_seconds:.2f}s[/dim]")

        # In batch mode, multiple files are analysed.  Inserting the stem of
        # the current target into the output path prevents each file from
        # silently overwriting the previous one.
        is_batch = len(targets) > 1

        def _batch_path(base_path: str, stem: str) -> str:
            """Insert <stem> before the extension of base_path when in batch mode."""
            if not is_batch:
                return base_path
            root, ext = os.path.splitext(base_path)
            return f"{root}_{stem}{ext}"

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

    return 0


if __name__ == "__main__":
    sys.exit(main())
