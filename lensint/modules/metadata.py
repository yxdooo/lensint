"""
Metadata module: EXIF, IPTC, XMP, ICC profiles, and software footprint analysis.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
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


def _check_timestamp_anomalies(report: MetadataReport):
    def parse_dt(s: Optional[str]) -> Optional[datetime]:
        if not s:
            return None
        s = str(s).strip()
        for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                pass
        return None

    dt_orig = parse_dt(report.datetime_original)
    dt_mod = parse_dt(report.datetime_modified)
    dt_dig = parse_dt(report.datetime_digitized)
    
    if hasattr(report, 'timestamp_anomalies'):
        if dt_orig and dt_mod and dt_mod < dt_orig:
            msg = "ModifyDate precedes DateTimeOriginal — possible clock forgery or metadata tampering."
            report.timestamp_anomalies.append(msg)
            report.software_footprint_findings.append(msg)
            
        if dt_orig and dt_dig and dt_dig < dt_orig:
            msg = "DateTimeDigitized precedes DateTimeOriginal — logical impossibility."
            report.timestamp_anomalies.append(msg)
            report.software_footprint_findings.append(msg)
            
        if dt_orig and dt_orig > datetime.now():
            msg = f"DateTimeOriginal ({report.datetime_original}) is in the future — metadata spoofing suspected."
            report.timestamp_anomalies.append(msg)
            report.software_footprint_findings.append(msg)
            
        if dt_orig and report.gps_info and "timestamp" in report.gps_info:
            gps_ts = report.gps_info.get("timestamp")
            if gps_ts:
                try:
                    dt_gps = datetime.fromisoformat(gps_ts.replace("Z", "+00:00"))
                    # strip tz for simple diff
                    dt_gps_naive = dt_gps.replace(tzinfo=None)
                    diff = abs((dt_gps_naive - dt_orig).total_seconds())
                    if diff > 86400:
                        msg = "GPS timestamp significantly differs from image timestamp."
                        report.timestamp_anomalies.append(msg)
                        report.software_footprint_findings.append(msg)
                except Exception:
                    pass


def _detect_social_media_provenance(raw_bytes: bytes, pil_img: Optional[Image.Image],
                                     has_exif: bool) -> Optional[str]:
    """Identify if the image was re-compressed / uploaded via social media platforms."""
    if not pil_img or has_exif:
        # Images directly from social media platforms have all standard EXIF stripped
        return None

    w, h = pil_img.size
    max_side = max(w, h)

    if raw_bytes.startswith(b"\xFF\xD8\xFF"):
        # WhatsApp: typically downscales to max 1600px or 1280px on long side, no EXIF
        if max_side in (1600, 1280, 1024, 800) and b"Exif" not in raw_bytes[:1024]:
            return "WhatsApp Media Compression (Stripped Metadata, Downscaled)"
        # Telegram: typically 1280px or 2560px
        if max_side in (1280, 2560) and b"JFIF" in raw_bytes[:64]:
            return "Telegram Photo Compression (Standard 1280/2560px envelope)"
        # Twitter / X: 1200px or 2048px Web standard
        if max_side in (1200, 2048, 4096) and b"Exif" not in raw_bytes[:512]:
            return "Twitter / X Re-encoded Media (Clean stripped headers)"
        # Instagram: standard 1080px width
        if w == 1080 and b"Exif" not in raw_bytes[:1024]:
            return "Instagram Standard Photo Format (1080px raster)"

    return None


def _calculate_ssim_grayscale(img1: Any, img2: Any) -> float:
    """Calculate Structural Similarity Index (SSIM) between two grayscale images."""
    import numpy as np
    from PIL import Image

    if isinstance(img1, Image.Image):
        arr1 = np.array(img1.convert("L"), dtype=np.float64)
    else:
        arr1 = np.array(img1, dtype=np.float64)

    if isinstance(img2, Image.Image):
        arr2 = np.array(img2.convert("L"), dtype=np.float64)
    else:
        arr2 = np.array(img2, dtype=np.float64)

    if arr1.shape != arr2.shape:
        raise ValueError("Images must have identical dimensions for SSIM calculation.")
    
    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2
    
    mu1 = np.mean(arr1)
    mu2 = np.mean(arr2)
    
    sigma1_sq = np.var(arr1)
    sigma2_sq = np.var(arr2)
    sigma12 = np.mean((arr1 - mu1) * (arr2 - mu2))
    
    ssim = ((2 * mu1 * mu2 + c1) * (2 * sigma12 + c2)) / ((mu1**2 + mu2**2 + c1) * (sigma1_sq + sigma2_sq + c2))
    return float(np.clip(ssim, -1.0, 1.0))


_calculate_ssim = _calculate_ssim_grayscale


def _check_thumbnail_mismatch(
    pil_img: Optional[Image.Image],
    raw_bytes: bytes,
) -> Tuple[bool, float, bool]:
    """
    Extract embedded EXIF thumbnail, resize main image to thumbnail dimensions,
    and compute SSIM score to detect tampering where main image was altered
    without updating the thumbnail.
    """
    if not pil_img:
        return False, 1.0, False

    try:
        import io
        import numpy as np

        # Search for embedded JPEG thumbnail inside raw bytes (common in EXIF IFD1)
        thumb_img = None
        # Try PIL native exif thumbnail with TIFF header offset correction
        if hasattr(pil_img, "_getexif"):
            exif = pil_img._getexif()
            if exif and 0x0201 in exif and 0x0202 in exif:
                thumb_offset = exif[0x0201]
                thumb_len = exif[0x0202]
                exif_start = raw_bytes.find(b"Exif\x00\x00")
                abs_offset = (exif_start + 6 + thumb_offset) if exif_start != -1 else thumb_offset
                if abs_offset + thumb_len <= len(raw_bytes):
                    thumb_data = raw_bytes[abs_offset : abs_offset + thumb_len]
                    if thumb_data.startswith(b"\xFF\xD8"):
                        try:
                            thumb_img = Image.open(io.BytesIO(thumb_data))
                        except Exception:
                            pass
                if thumb_img is None and thumb_offset + thumb_len <= len(raw_bytes):
                    thumb_data = raw_bytes[thumb_offset : thumb_offset + thumb_len]
                    if thumb_data.startswith(b"\xFF\xD8"):
                        try:
                            thumb_img = Image.open(io.BytesIO(thumb_data))
                        except Exception:
                            pass

        # Fallback: scan for second SOI marker \xFF\xD8 inside EXIF header region
        if thumb_img is None and len(raw_bytes) > 2048:
            exif_start = raw_bytes.find(b"Exif\x00\x00")
            if exif_start != -1:
                second_soi = raw_bytes.find(b"\xFF\xD8\xFF", exif_start + 6)
                if second_soi != -1 and second_soi < 65536:
                    second_eoi = raw_bytes.find(b"\xFF\xD9", second_soi)
                    if second_eoi != -1 and second_eoi > second_soi:
                        thumb_data = raw_bytes[second_soi : second_eoi + 2]
                        try:
                            t_candidate = Image.open(io.BytesIO(thumb_data))
                            t_candidate.load()
                            if t_candidate.size[0] >= 32 and t_candidate.size[1] >= 32:
                                thumb_img = t_candidate
                        except Exception:
                            pass

        if thumb_img is not None:
            tw, th = thumb_img.size
            main_downscaled = pil_img.resize((tw, th), Image.LANCZOS)
            ssim_score = _calculate_ssim(thumb_img, main_downscaled)
            # If SSIM is low, main image was manipulated without updating thumbnail
            mismatch = ssim_score < 0.75
            return mismatch, round(ssim_score, 3), True

        return False, 1.0, False
    except Exception:
        return False, 1.0, False


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

    # ── IPTC Parsing ────────────────────────────────────────────────────────
    # PIL exposes raw IPTC bytes in pil_img.info["photoshop"] (as a dict
    # keyed by IPTC block ID 0x0404) or in pil_img.info["iptc"].
    # We parse record-2 (application record) tag/value pairs manually.
    IPTC_TAGS = {
        5:  "ObjectName",
        10: "Urgency",
        15: "Category",
        20: "SupplementalCategories",
        25: "Keywords",
        40: "SpecialInstructions",
        55: "DateCreated",
        60: "TimeCreated",
        65: "OriginatingProgram",
        70: "ProgramVersion",
        80: "Byline",
        85: "BylineTitle",
        90: "City",
        92: "SubLocation",
        95: "Province",
        100: "CountryCode",
        101: "Country",
        103: "OriginalTransmissionReference",
        105: "Headline",
        110: "Credit",
        115: "Source",
        116: "CopyrightNotice",
        118: "Contact",
        120: "Caption",
        122: "WriterEditor",
    }

    try:
        iptc_raw: Optional[bytes] = None
        if pil_img is not None:
            if "photoshop" in pil_img.info:
                photoshop_block = pil_img.info["photoshop"]
                # Key 0x0404 is the IPTC-NAA block inside Photoshop metadata
                if isinstance(photoshop_block, dict) and 0x0404 in photoshop_block:
                    iptc_raw = photoshop_block[0x0404]
                elif isinstance(photoshop_block, bytes):
                    # Search for IPTC marker 8BIM + 0x0404 manually
                    marker = b"8BIM\x04\x04"
                    idx = photoshop_block.find(marker)
                    if idx != -1:
                        size_offset = idx + 6 + 2  # skip 8BIM(4) + type(2) + pascal string(2)
                        if size_offset + 4 <= len(photoshop_block):
                            block_len = int.from_bytes(photoshop_block[size_offset: size_offset + 4], "big")
                            iptc_raw = photoshop_block[size_offset + 4: size_offset + 4 + block_len]
            elif "iptc" in pil_img.info:
                iptc_raw = pil_img.info["iptc"]

        if iptc_raw:
            iptc_dict: Dict[str, Any] = {}
            i = 0
            while i < len(iptc_raw):
                if i + 5 > len(iptc_raw):
                    break
                # IPTC tag structure: 0x1C (marker) | record | dataset | length(2)
                if iptc_raw[i] != 0x1C:
                    i += 1
                    continue
                record = iptc_raw[i + 1]
                dataset = iptc_raw[i + 2]
                tag_len = int.from_bytes(iptc_raw[i + 3: i + 5], "big")
                i += 5
                if i + tag_len > len(iptc_raw):
                    break
                value_bytes = iptc_raw[i: i + tag_len]
                i += tag_len
                # Only process record 2 (application record)
                if record == 2:
                    tag_name = IPTC_TAGS.get(dataset, f"IPTC_{dataset}")
                    value_str = value_bytes.decode("utf-8", errors="replace").strip()
                    if tag_name in iptc_dict:
                        existing = iptc_dict[tag_name]
                        if isinstance(existing, list):
                            existing.append(value_str)
                        else:
                            iptc_dict[tag_name] = [existing, value_str]
                    else:
                        iptc_dict[tag_name] = value_str
            if iptc_dict:
                report.iptc_present = True
                report.iptc_data = iptc_dict
    except Exception:
        pass
    # ────────────────────────────────────────────────────────────────────────

    software_candidates = []
    if report.software:
        software_candidates.append(report.software)
    if "CreatorTool" in report.xmp_data:
        software_candidates.append(report.xmp_data["CreatorTool"])
    if "History" in report.xmp_data:
        software_candidates.append(str(report.xmp_data["History"]))
    if "OriginatingProgram" in report.iptc_data:
        software_candidates.append(str(report.iptc_data["OriginatingProgram"]))

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

    _check_timestamp_anomalies(report)

    # Social Media Provenance
    soc_prov = _detect_social_media_provenance(raw_bytes, pil_img, report.exif_present)
    report.social_media_provenance = soc_prov
    if soc_prov:
        report.software_footprint_findings.append(f"Social Media Footprint: {soc_prov}.")

    # Thumbnail SSIM Mismatch
    thumb_mismatch, ssim_val, thumb_found = _check_thumbnail_mismatch(pil_img, raw_bytes)
    report.thumbnail_extracted = thumb_found
    report.thumbnail_ssim_score = ssim_val
    report.thumbnail_mismatch_detected = thumb_mismatch
    if thumb_mismatch:
        report.software_footprint_findings.append(
            f"EXIF Thumbnail Discrepancy (SSIM: {ssim_val:.2f}/1.0): Embedded thumbnail differs significantly from main image — indicates selective image manipulation."
        )

    return report
