import os
import shutil
import subprocess
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def check_exiftool_installed() -> bool:
    """
    Checks if exiftool is available in the system PATH.
    """
    return shutil.which("exiftool") is not None

def require_exiftool():
    """
    Halts execution if exiftool is not found, providing a clear error message.
    """
    if not check_exiftool_installed():
        print("\n" + "="*60)
        print("CRITICAL ERROR: ExifTool is not installed or not in PATH.")
        print("="*60)
        print("LENSINT requires Phil Harvey's ExifTool for court-grade")
        print("metadata extraction (MakerNotes, Embedded Previews, etc).")
        print("\nInstallation Instructions:")
        print("  Windows: Download from https://exiftool.org/, rename to exiftool.exe, and add to PATH.")
        print("  Ubuntu/Debian: sudo apt-get install libimage-exiftool-perl")
        print("  macOS (Homebrew): brew install exiftool")
        print("="*60 + "\n")
        import sys
        sys.exit(1)
