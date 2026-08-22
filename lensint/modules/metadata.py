"""
Metadata module: EXIF, IPTC, XMP, ICC profiles, and software footprint analysis.
"""

import re
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET
from PIL import Image, ExifTags

from lensint.core.models import MetadataReport
from lensint.utils.gps import parse_gps_data

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
]


def _format_tag_value(val: Any) -> Any:
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace").strip("\x00 \r\n\t")
        except Exception:
            return f"<binary: {len(val)} bytes>"
    if hasattr(val, "numerator") and hasattr(val, "denominator"):
        if val.denominator == 1:
            return val.numerator
        return f"{val.numerator}/{val.denominator}"
    if isinstance(val, (tuple, list)):
        return [_format_tag_value(item) for item in val]
    if isinstance(val, dict):
        return {str(k): _format_tag_value(v) for k, v in val.items()}
    return str(val) if not isinstance(val, (int, float, bool)) else val


def _extract_xmp_data(raw_bytes: bytes) -> Dict[str, Any]:
    xmp_dict = {}
    xmp_start = raw_bytes.find(b"<x:xmpmeta")
    if xmp_start == -1:
        xmp_start = raw_bytes.find(b"<?xpacket begin")

    if xmp_start != -1:
        xmp_end = raw_bytes.find(b"</x:xmpmeta>", xmp_start)
        if xmp_end == -1:
            xmp_end = raw_bytes.find(b"<?xpacket end", xmp_start)
        else:
            xmp_end += len(b"</x:xmpmeta>")

        if xmp_end != -1 and xmp_end > xmp_start:
            xmp_xml = raw_bytes[xmp_start:xmp_end]
            try:
                root = ET.fromstring(xmp_xml.decode("utf-8", errors="replace"))
                for elem in root.iter():
                    tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                    text = elem.text.strip() if elem.text else ""
                    if text and tag_name not in ["xmpmeta", "RDF", "Description"]:
                        xmp_dict[tag_name] = text
                    for attr_k, attr_v in elem.attrib.items():
                        attr_clean = attr_k.split("}")[-1] if "}" in attr_k else attr_k
                        if attr_clean not in ["about", "prefix"]:
                            xmp_dict[attr_clean] = attr_v
            except Exception:
                xmp_text = xmp_xml.decode("utf-8", errors="replace")
                for key in ["CreatorTool", "DocumentID", "InstanceID", "Format", "CreateDate", "ModifyDate", "History"]:
                    pattern = key + r"""=["']([^"']+)["']"""
                    match = re.search(pattern, xmp_text, re.IGNORECASE)
                    if match:
                        xmp_dict[key] = match.group(1)
    return xmp_dict


def analyze_metadata(raw_bytes: bytes, pil_img: Optional[Image.Image]) -> MetadataReport:
    report = MetadataReport()
    exif_raw = {}
    gps_raw = {}

    if pil_img is not None:
        try:
            exif_data = pil_img.getexif()
            if exif_data:
                report.exif_present = True
                for tag_id, value in exif_data.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    exif_raw[tag_name] = _format_tag_value(value)

                try:
                    for ifd_id in ExifTags.IFD:
                        try:
                            ifd_data = exif_data.get_ifd(ifd_id)
                            if ifd_data:
                                ifd_name = ifd_id.name
                                for tag_id, value in ifd_data.items():
                                    if ifd_name == "GPSInfo":
                                        sub_tag_name = ExifTags.GPSTAGS.get(tag_id, str(tag_id))
                                        gps_raw[sub_tag_name] = value
                                    else:
                                        sub_tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                                    exif_raw[f"{ifd_name}:{sub_tag_name}"] = _format_tag_value(value)
                        except Exception:
                            pass
                except Exception:
                    pass

                if not gps_raw and hasattr(pil_img, "_getexif"):
                    legacy_exif = pil_img._getexif()
                    if legacy_exif and 34853 in legacy_exif:
                        gps_info_raw = legacy_exif[34853]
                        for k, v in gps_info_raw.items():
                            sub_name = ExifTags.GPSTAGS.get(k, str(k))
                            gps_raw[sub_name] = v
        except Exception:
            pass

    report.raw_tags = exif_raw
    report.camera_make = exif_raw.get("Make") or exif_raw.get("Exif:Make")
    report.camera_model = exif_raw.get("Model") or exif_raw.get("Exif:Model")
    report.lens_model = exif_raw.get("LensModel") or exif_raw.get("Exif:LensModel")
    report.software = exif_raw.get("Software") or exif_raw.get("Exif:Software")
    report.artist = exif_raw.get("Artist") or exif_raw.get("Exif:Artist")
    report.copyright = exif_raw.get("Copyright") or exif_raw.get("Exif:Copyright")
    report.device_serial_number = exif_raw.get("BodySerialNumber") or exif_raw.get("SerialNumber")

    report.datetime_original = exif_raw.get("DateTimeOriginal") or exif_raw.get("Exif:DateTimeOriginal")
    report.datetime_digitized = exif_raw.get("DateTimeDigitized") or exif_raw.get("Exif:DateTimeDigitized")
    report.datetime_modified = exif_raw.get("DateTime") or exif_raw.get("Exif:DateTime")

    iso_val = exif_raw.get("ISOSpeedRatings") or exif_raw.get("Exif:ISOSpeedRatings") or exif_raw.get("PhotographicSensitivity")
    if iso_val:
        try:
            report.iso = int(iso_val if not isinstance(iso_val, list) else iso_val[0])
        except Exception:
            pass

    report.exposure_time = str(exif_raw.get("ExposureTime") or exif_raw.get("Exif:ExposureTime") or "")
    report.f_number = str(exif_raw.get("FNumber") or exif_raw.get("Exif:FNumber") or "")
    report.focal_length = str(exif_raw.get("FocalLength") or exif_raw.get("Exif:FocalLength") or "")
    report.flash = str(exif_raw.get("Flash") or exif_raw.get("Exif:Flash") or "")
    report.metering_mode = str(exif_raw.get("MeteringMode") or exif_raw.get("Exif:MeteringMode") or "")

    if gps_raw:
        parsed_gps = parse_gps_data(gps_raw)
        if parsed_gps:
            report.gps_info = parsed_gps

    xmp_data = _extract_xmp_data(raw_bytes)
    if xmp_data:
        report.xmp_present = True
        report.xmp_data = xmp_data
        if not report.software and "CreatorTool" in xmp_data:
            report.software = xmp_data["CreatorTool"]

    if pil_img and "icc_profile" in pil_img.info:
        icc_raw = pil_img.info["icc_profile"]
        report.icc_profile = {
            "present": True,
            "raw_size_bytes": len(icc_raw),
        }
        desc_match = re.search(rb"desc[\x01-\x20\x00]+([a-zA-Z0-9 \._\-]+)", icc_raw)
        if desc_match:
            try:
                report.icc_profile["name"] = desc_match.group(1).decode("ascii", errors="ignore").strip()
            except Exception:
                pass

    software_candidates = []
    if report.software:
        software_candidates.append(report.software)
    if "CreatorTool" in report.xmp_data:
        software_candidates.append(report.xmp_data["CreatorTool"])
    if "History" in report.xmp_data:
        software_candidates.append(str(report.xmp_data["History"]))

    combined_software_str = " ".join(software_candidates).lower()

    for pattern, name in KNOWN_EDITING_SOFTWARE:
        if pattern in combined_software_str:
            finding = f"Image metadata contains traces of digital manipulation software: {name}."
            if finding not in report.software_footprint_findings:
                report.software_footprint_findings.append(finding)

    if report.datetime_original and report.datetime_modified:
        if report.datetime_original != report.datetime_modified:
            report.software_footprint_findings.append(
                f"Timestamp modification detected: Original ({report.datetime_original}) "
                f"differs from Modified ({report.datetime_modified})."
            )

    return report
