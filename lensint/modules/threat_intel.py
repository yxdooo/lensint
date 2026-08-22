import json, urllib.parse, urllib.request
from typing import Any, Dict, List, Optional
from lensint.core.models import ThreatIntelReport

def reverse_geocode(latitude: float, longitude: float, timeout: int = 3) -> Optional[Dict[str, str]]:
    url = f'https://nominatim.openstreetmap.org/reverse?format=json&lat={latitude}&lon={longitude}&zoom=18&addressdetails=1'
    req = urllib.request.Request(url, headers={'User-Agent': 'Lensint-Forensics/2.0'})
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

def generate_threat_intel_links(sha256_hash: str, ips: List[str], domains: List[str], urls: List[str]) -> ThreatIntelReport:
    report = ThreatIntelReport()
    if sha256_hash:
        report.virustotal_file_url = f'https://www.virustotal.com/gui/file/{sha256_hash}'
        report.hybrid_analysis_url = f'https://www.hybrid-analysis.com/sample/{sha256_hash}'

    for ip in ips[:10]:
        report.ip_lookups[ip] = {
            'virustotal': f'https://www.virustotal.com/gui/ip-address/{ip}',
            'abuseipdb': f'https://www.abuseipdb.com/check/{ip}',
            'shodan': f'https://www.shodan.io/host/{ip}',
            'threatfox': f'https://threatfox.abuse.ch/browse.php?search=ioc:{ip}'
        }

    for dom in domains[:10]:
        clean = dom.replace('http://', '').replace('https://', '').split('/')[0]
        report.domain_lookups[clean] = {
            'virustotal': f'https://www.virustotal.com/gui/domain/{clean}',
            'urlscan': f'https://urlscan.io/domain/{clean}',
            'threatfox': f'https://threatfox.abuse.ch/browse.php?search=ioc:{clean}'
        }

    report.reverse_image_engines = {
        'Google Lens': 'https://lens.google.com/upload',
        'Bing Visual Search': 'https://www.bing.com/visualsearch',
        'Yandex Images': 'https://yandex.com/images/search?rpt=imageview',
        'TinEye': 'https://tineye.com/'
    }
    return report
