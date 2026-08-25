import json, urllib.parse, urllib.request
from typing import Any, Dict, List, Optional
from lensint.config import config
from lensint.core.models import ThreatIntelReport

def reverse_geocode(latitude: float, longitude: float, timeout: Optional[int] = None) -> Optional[Dict[str, str]]:
    timeout = timeout or config.geolookup_timeout_seconds
    url = f'https://nominatim.openstreetmap.org/reverse?format=json&lat={latitude}&lon={longitude}&zoom=18&addressdetails=1'
    req = urllib.request.Request(url, headers={'User-Agent': config.nominatim_user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                addr = data.get('address', {})
                return {
                    'display_name': data.get('display_name', ''),
                    'road': addr.get('road') or addr.get('pedestrian') or '',
                    'suburb': addr.get('suburb') or addr.get('neighbourhood') or '',
                    'city': addr.get('city') or addr.get('town') or addr.get('village') or '',
                    'state': addr.get('state') or addr.get('province') or '',
                    'country': addr.get('country') or '',
                    'country_code': (addr.get('country_code') or '').upper(),
                    'postcode': addr.get('postcode') or ''
                }
    except Exception:
        return None
    return None

def query_virustotal_file_api(sha256_hash: str, api_key: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """Query VirusTotal v3 API for file hash reputation and detection statistics."""
    if not api_key or not sha256_hash:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key, "User-Agent": "LENSINT-Forensics"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attrs.get("reputation", 0),
                    "meaningful_name": attrs.get("meaningful_name"),
                }
    except Exception:
        return None
    return None


def query_abuseipdb_api(ip: str, api_key: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """Query AbuseIPDB v2 API for IP abuse confidence score."""
    if not api_key or not ip:
        return None
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                d = data.get("data", {})
                return {
                    "ip": ip,
                    "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                    "country_code": d.get("countryCode"),
                    "isp": d.get("isp"),
                    "total_reports": d.get("totalReports", 0),
                }
    except Exception:
        return None
    return None


def generate_threat_intel_links(
    sha256_hash: str,
    ips: List[str],
    domains: List[str],
    urls: List[str],
    query_live_api: bool = True,
) -> ThreatIntelReport:
    """Generate threat intel portal links and execute live API queries if API keys are configured."""
    report = ThreatIntelReport()
    if sha256_hash:
        report.virustotal_file_url = f"https://www.virustotal.com/gui/file/{sha256_hash}"
        report.hybrid_analysis_url = f"https://www.hybrid-analysis.com/sample/{sha256_hash}"

        # Live VT query if API key is provided
        if query_live_api and getattr(config, "virustotal_api_key", None):
            vt_data = query_virustotal_file_api(sha256_hash, config.virustotal_api_key)
            if vt_data:
                report.live_reputation["virustotal"] = vt_data

    for ip in ips[:10]:
        report.ip_lookups[ip] = {
            "virustotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
            "abuseipdb": f"https://www.abuseipdb.com/check/{ip}",
            "shodan": f"https://www.shodan.io/host/{ip}",
            "threatfox": f"https://threatfox.abuse.ch/browse.php?search=ioc:{ip}",
        }
        if query_live_api and getattr(config, "abuseipdb_api_key", None):
            abuse_res = query_abuseipdb_api(ip, config.abuseipdb_api_key)
            if abuse_res:
                report.live_reputation[f"abuseipdb_{ip}"] = abuse_res

    for dom in domains[:10]:
        clean = dom.replace("http://", "").replace("https://", "").split("/")[0]
        report.domain_lookups[clean] = {
            "virustotal": f"https://www.virustotal.com/gui/domain/{clean}",
            "urlscan": f"https://urlscan.io/domain/{clean}",
            "threatfox": f"https://threatfox.abuse.ch/browse.php?search=ioc:{clean}",
        }

    report.reverse_image_engines = {
        "Google Lens": "https://lens.google.com/upload",
        "Bing Visual Search": "https://www.bing.com/visualsearch",
        "Yandex Images": "https://yandex.com/images/search?rpt=imageview",
        "TinEye": "https://tineye.com/",
    }
    return report
