import re
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
import exiftool

from lensint.core.models import MetadataReport
from lensint.utils.gps import parse_gps_data

logger = logging.getLogger(__name__)

KNOWN_EDITING_SOFTWARE = [
    ("photoshop", "Adobe Photoshop"),
    ("lightroom", "Adobe Lightroom"),
    ("gimp", "GIMP (GNU Image Manipulation Program)"),
    ("canva", "Canva"),
    ("snapseed", "Snapseed"),
    ("vsco", "VSCO"),
    ("photomator", "Photomator / Pixelmator"),
    ("pixelmator", "Pixelmator"),
    ("paint.net", "Paint.NET"),
    ("procreate", "Procreate"),
    ("figma", "Figma"),
    ("affinity", "Serif Affinity"),
    ("coreldraw", "CorelDRAW"),
    ("blender", "Blender 3D Render"),
    ("midjourney", "Midjourney AI Generator"),
    ("stable diffusion", "Stable Diffusion AI Generator"),
    ("dall-e", "DALL-E AI Generator"),
    ("firefly", "Adobe Firefly AI"),
    ("topaz", "Topaz Labs Video/Photo AI"),
]

def analyze_metadata(file_path: str, raw_bytes: bytes, pil_img: Optional[Any]) -> MetadataReport:
    """
    Extracts deep metadata using Phil Harvey's ExifTool.
    Returns a populated MetadataReport object.
    (raw_bytes and pil_img are kept for backwards compatibility in the function signature)
    """
    report = MetadataReport(
        exif={}, 
        xmp={}, 
        iptc={}, 
        software_footprint_findings=[], 
        timestamp_anomalies=[]
    )
    
    try:
        with exiftool.ExifToolHelper() as et:
            # -n reads numeric values, -G1 groups tags (e.g. EXIF:Make)
            # but we'll fetch default tags for rich strings and specific group prefixes
            metadata_list = et.get_metadata(file_path)
            
            if not metadata_list:
                return report
                
            raw_meta = metadata_list[0]
    except Exception as e:
        logger.error(f"ExifTool extraction failed: {e}")
        report.software_footprint_findings.append(f"ExifTool Error: {str(e)}")
        return report

    software_hints = []
    
    for key, value in raw_meta.items():
        if not isinstance(value, str):
            value_str = str(value)
        else:
            value_str = value
            
        # Group tags loosely for the report
        if key.startswith("EXIF:"):
            report.exif[key.split(":")[-1]] = value
        elif key.startswith("XMP:"):
            report.xmp[key.split(":")[-1]] = value
        elif key.startswith("IPTC:"):
            report.iptc[key.split(":")[-1]] = value
        elif key.startswith("MakerNotes:"):
            # ExifTool automatically parses proprietary MakerNotes
            report.exif[f"MakerNote_{key.split(':')[-1]}"] = value
        else:
            # Store general File info or other tags in exif dictionary
            report.exif[key] = value

        # Check for software footprints across ALL text metadata
        val_lower = value_str.lower()
        if "history" in key.lower() or "software" in key.lower() or "creatortool" in key.lower():
            software_hints.append(value_str)
        
        for soft_id, soft_name in KNOWN_EDITING_SOFTWARE:
            if soft_id in val_lower:
                msg = f"Detected {soft_name} trace in metadata field [{key}]"
                if msg not in report.software_footprint_findings:
                    report.software_footprint_findings.append(msg)

    # Core EXIF assignments
    report.make = raw_meta.get("EXIF:Make") or raw_meta.get("IFD0:Make")
    report.model = raw_meta.get("EXIF:Model") or raw_meta.get("IFD0:Model")
    report.software = raw_meta.get("EXIF:Software") or raw_meta.get("IFD0:Software") or raw_meta.get("XMP:CreatorTool")
    report.datetime_original = raw_meta.get("EXIF:DateTimeOriginal") or raw_meta.get("Composite:SubSecDateTimeOriginal")
    report.datetime_modified = raw_meta.get("EXIF:ModifyDate") or raw_meta.get("IFD0:ModifyDate")
    report.datetime_digitized = raw_meta.get("EXIF:CreateDate")
    report.color_space = raw_meta.get("EXIF:ColorSpace")
    report.lens_model = raw_meta.get("EXIF:LensModel") or raw_meta.get("Composite:LensID")

    # GPS coordinates
    lat = raw_meta.get("Composite:GPSLatitude")
    lon = raw_meta.get("Composite:GPSLongitude")
    if lat is not None and lon is not None:
        report.gps_info = {
            "latitude": lat,
            "longitude": lon,
            "altitude": raw_meta.get("Composite:GPSAltitude"),
            "timestamp": raw_meta.get("Composite:GPSDateTime")
        }

    # C2PA & Provenance
    if raw_meta.get("XMP:Provenance") or raw_meta.get("File:JUMBF"):
        report.software_footprint_findings.append("C2PA / Content Credentials provenance data found.")

    _check_timestamp_anomalies(report)

    return report


def _check_timestamp_anomalies(report: MetadataReport):
    def parse_dt(s: Optional[str]) -> Optional[datetime]:
        if not s:
            return None
        s = str(s).strip()
        s = s.split("-")[0].split("+")[0].strip() # strip timezone offsets if any
        for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                pass
        return None

    dt_orig = parse_dt(report.datetime_original)
    dt_mod = parse_dt(report.datetime_modified)
    dt_dig = parse_dt(report.datetime_digitized)
    
    if not hasattr(report, 'timestamp_anomalies'):
        report.timestamp_anomalies = []

    if dt_orig and dt_mod and dt_mod < dt_orig:
        msg = "ModifyDate precedes DateTimeOriginal - possible clock forgery or metadata tampering."
        report.timestamp_anomalies.append(msg)
        report.software_footprint_findings.append(msg)
        
    if dt_orig and dt_dig and dt_dig < dt_orig:
        msg = "CreateDate precedes DateTimeOriginal - logical impossibility."
        report.timestamp_anomalies.append(msg)
        report.software_footprint_findings.append(msg)
        
    if dt_orig and dt_orig > datetime.now():
        msg = f"DateTimeOriginal ({report.datetime_original}) is in the future - metadata spoofing suspected."
        report.timestamp_anomalies.append(msg)
        report.software_footprint_findings.append(msg)
def _detect_social_media_provenance(raw_bytes, pil_img, has_exif):
    return None

def _extract_xmp_data(raw_bytes):
    return {}

def _calculate_ssim_grayscale(img1, img2):
    return 1.0
def _calculate_ssim(img1, img2):
    return 1.0
def _check_thumbnail_mismatch(raw_bytes, pil_img, has_exif):
    return False
