import os
import shutil
import logging
import sys

logger = logging.getLogger(__name__)

def check_binary_installed(name: str) -> bool:
    return shutil.which(name) is not None

def require_exiftool():
    if not check_binary_installed("exiftool"):
        print("\n" + "="*60)
        print("CRITICAL ERROR: ExifTool is not installed or not in PATH.")
        print("="*60)
        print("LENSINT requires Phil Harvey's ExifTool for court-grade")
        print("metadata extraction.")
        print("\nInstallation Instructions:")
        print("  Windows: Download from https://exiftool.org/, rename to exiftool.exe, and add to PATH.")
        print("  Ubuntu/Debian: sudo apt-get install libimage-exiftool-perl")
        print("  macOS (Homebrew): brew install exiftool")
        print("="*60 + "\n")
        sys.exit(1)

def require_ffmpeg():
    if not check_binary_installed("ffmpeg"):
        print("\n" + "="*60)
        print("CRITICAL ERROR: FFmpeg is not installed or not in PATH.")
        print("="*60)
        print("LENSINT 4.5 requires FFmpeg for Audio Deepfake and Video extraction.")
        print("\nInstallation Instructions:")
        print("  Windows: winget install ffmpeg (or download from ffmpeg.org and add to PATH)")
        print("  Ubuntu/Debian: sudo apt-get install ffmpeg")
        print("  macOS (Homebrew): brew install ffmpeg")
        print("="*60 + "\n")
        sys.exit(1)

def run_all_checks():
    require_exiftool()
    require_ffmpeg()
