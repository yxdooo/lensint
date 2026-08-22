"""
GPS coordinate conversion, formatting, and map URL generation.
"""

from typing import Any, Dict, Optional


def _convert_to_degrees(value: Any) -> Optional[float]:
    """
    Convert EXIF GPS coordinates (degrees, minutes, seconds) to decimal degrees.
    """
    if not value or len(value) < 3:
        return None

    try:
        def _to_float(v: Any) -> float:
            if hasattr(v, "numerator") and hasattr(v, "denominator"):
                return float(v.numerator) / float(v.denominator) if v.denominator != 0 else 0.0
            if isinstance(v, (tuple, list)) and len(v) == 2:
                return float(v[0]) / float(v[1]) if v[1] != 0 else 0.0
            return float(v)

        d = _to_float(value[0])
        m = _to_float(value[1])
        s = _to_float(value[2])

        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return None


def parse_gps_data(gps_tags: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse raw GPS EXIF dictionary into a structured GPS record with decimal coordinates.
    """
    if not gps_tags:
        return None

    lat_val = gps_tags.get("GPSLatitude")
    lat_ref = gps_tags.get("GPSLatitudeRef", "N")
    lon_val = gps_tags.get("GPSLongitude")
    lon_ref = gps_tags.get("GPSLongitudeRef", "E")

    if not lat_val or not lon_val:
        return None

    lat_dec = _convert_to_degrees(lat_val)
    lon_dec = _convert_to_degrees(lon_val)

    if lat_dec is None or lon_dec is None:
        return None

    if str(lat_ref).upper() in ["S", "SOUTH"]:
        lat_dec = -lat_dec

    if str(lon_ref).upper() in ["W", "WEST"]:
        lon_dec = -lon_dec

    altitude = None
    alt_val = gps_tags.get("GPSAltitude")
    if alt_val is not None:
        try:
            if hasattr(alt_val, "numerator") and hasattr(alt_val, "denominator"):
                alt_num = float(alt_val.numerator) / float(alt_val.denominator) if alt_val.denominator != 0 else 0.0
            elif isinstance(alt_val, (tuple, list)) and len(alt_val) == 2:
                alt_num = float(alt_val[0]) / float(alt_val[1]) if alt_val[1] != 0 else 0.0
            else:
                alt_num = float(alt_val)

            alt_ref = gps_tags.get("GPSAltitudeRef", 0)
            if alt_ref == 1 or str(alt_ref) == "1":
                alt_num = -alt_num
            altitude = round(alt_num, 2)
        except Exception:
            altitude = None

    gps_time = None
    time_val = gps_tags.get("GPSTimeStamp")
    date_val = gps_tags.get("GPSDateStamp")
    if time_val:
        try:
            def _to_int(v: Any) -> int:
                if hasattr(v, "numerator") and hasattr(v, "denominator"):
                    return int(v.numerator / v.denominator) if v.denominator != 0 else 0
                if isinstance(v, (tuple, list)) and len(v) == 2:
                    return int(v[0] / v[1]) if v[1] != 0 else 0
                return int(v)

            h = _to_int(time_val[0])
            m = _to_int(time_val[1])
            s = _to_int(time_val[2])
            time_str = f"{h:02d}:{m:02d}:{s:02d} UTC"
            if date_val:
                gps_time = f"{date_val} {time_str}"
            else:
                gps_time = time_str
        except Exception:
            gps_time = None

    lat_dec = round(lat_dec, 6)
    lon_dec = round(lon_dec, 6)

    lat_cardinal = "S" if lat_dec < 0 else "N"
    lon_cardinal = "W" if lon_dec < 0 else "E"
    dms_str = f"{abs(lat_dec):.4f}° {lat_cardinal}, {abs(lon_dec):.4f}° {lon_cardinal}"

    google_maps_url = f"https://www.google.com/maps?q={lat_dec},{lon_dec}"
    osm_url = f"https://www.openstreetmap.org/?mlat={lat_dec}&mlon={lon_dec}#map=16/{lat_dec}/{lon_dec}"

    return {
        "latitude": lat_dec,
        "longitude": lon_dec,
        "dms": dms_str,
        "altitude_meters": altitude,
        "timestamp": gps_time,
        "google_maps_url": google_maps_url,
        "openstreetmap_url": osm_url,
    }
