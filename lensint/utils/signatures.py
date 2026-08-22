"""
File signatures, magic bytes, and container EOF definitions.
"""

from typing import Any, Dict, List

IMAGE_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "JPEG",
        "mime": "image/jpeg",
        "extensions": [".jpg", ".jpeg", ".jpe", ".jfif"],
        "header": b"\xFF\xD8\xFF",
        "eof_marker": b"\xFF\xD9",
    },
    {
        "name": "PNG",
        "mime": "image/png",
        "extensions": [".png"],
        "header": b"\x89PNG\r\n\x1a\n",
        "eof_marker": b"IEND\xaeB`\x82",
    },
    {
        "name": "GIF87a",
        "mime": "image/gif",
        "extensions": [".gif"],
        "header": b"GIF87a",
        "eof_marker": b"\x00\x3B",
    },
    {
        "name": "GIF89a",
        "mime": "image/gif",
        "extensions": [".gif"],
        "header": b"GIF89a",
        "eof_marker": b"\x00\x3B",
    },
    {
        "name": "BMP",
        "mime": "image/bmp",
        "extensions": [".bmp", ".dib"],
        "header": b"BM",
        "eof_marker": None,
    },
    {
        "name": "TIFF (Little Endian)",
        "mime": "image/tiff",
        "extensions": [".tif", ".tiff"],
        "header": b"II\x2A\x00",
        "eof_marker": None,
    },
    {
        "name": "TIFF (Big Endian)",
        "mime": "image/tiff",
        "extensions": [".tif", ".tiff"],
        "header": b"MM\x00\x2A",
        "eof_marker": None,
    },
    {
        "name": "WEBP",
        "mime": "image/webp",
        "extensions": [".webp"],
        "header": b"RIFF",
        "eof_marker": None,
    },
    {
        "name": "ICO",
        "mime": "image/x-icon",
        "extensions": [".ico"],
        "header": b"\x00\x00\x01\x00",
        "eof_marker": None,
    },
    {
        "name": "Photoshop Document (PSD)",
        "mime": "image/vnd.adobe.photoshop",
        "extensions": [".psd"],
        "header": b"8BPS",
        "eof_marker": None,
    },
]

EMBEDDED_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "ZIP Archive",
        "category": "Archive",
        "pattern": b"PK\x03\x04",
        "description": "Standard ZIP Archive header (polyglot or payload)",
    },
    {
        "name": "ZIP Central Directory",
        "category": "Archive",
        "pattern": b"PK\x01\x02",
        "description": "ZIP Central Directory record",
    },
    {
        "name": "RAR Archive v4",
        "category": "Archive",
        "pattern": b"Rar!\x1a\x07\x00",
        "description": "RAR Archive format v4",
    },
    {
        "name": "RAR Archive v5",
        "category": "Archive",
        "pattern": b"Rar!\x1a\x07\x01\x00",
        "description": "RAR Archive format v5",
    },
    {
        "name": "7-Zip Archive",
        "category": "Archive",
        "pattern": b"7z\xbc\xaf\'\x1c",
        "description": "7-Zip compressed archive",
    },
    {
        "name": "GZIP Archive",
        "category": "Archive",
        "pattern": b"\x1f\x8b\x08",
        "description": "GZIP compressed archive",
    },
    {
        "name": "BZIP2 Archive",
        "category": "Archive",
        "pattern": b"BZh",
        "description": "BZIP2 compressed archive",
    },
    {
        "name": "XZ Archive",
        "category": "Archive",
        "pattern": b"\xfd7zXZ\x00",
        "description": "XZ compressed archive",
    },
    {
        "name": "Windows Executable (PE/MZ)",
        "category": "Executable",
        "pattern": b"MZ",
        "description": "DOS MZ header / Windows PE Executable",
    },
    {
        "name": "Linux Executable (ELF)",
        "category": "Executable",
        "pattern": b"\x7fELF",
        "description": "Linux Executable and Linkable Format",
    },
    {
        "name": "PDF Document",
        "category": "Document",
        "pattern": b"%PDF-",
        "description": "Embedded PDF document stream",
    },
    {
        "name": "SQLite 3 Database",
        "category": "Database",
        "pattern": b"SQLite format 3\x00",
        "description": "Embedded SQLite database",
    },
    {
        "name": "PHP Script Tag",
        "category": "Webshell/Script",
        "pattern": b"<?php",
        "description": "PHP execution script tag",
    },
    {
        "name": "Shell Script Header",
        "category": "Script",
        "pattern": b"#!/bin/sh",
        "description": "Unix shell script shebang",
    },
    {
        "name": "Bash Script Header",
        "category": "Script",
        "pattern": b"#!/bin/bash",
        "description": "Bash script shebang",
    },
    {
        "name": "Python Script Header",
        "category": "Script",
        "pattern": b"#!/usr/bin/env python",
        "description": "Python script shebang",
    },
]
