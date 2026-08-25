"""
Strings and IOC Extraction Module:
Extract ASCII/UTF-16 strings and hunt for IOCs (IPs, URLs, Base64, Shell commands, Crypto wallets).
"""

import base64
import ipaddress
import re
from typing import Any, Dict, List
from lensint.core.models import StringsReport

RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
RE_URL = re.compile(r"\b(?:https?|ftp|ws|wss)://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]+", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|gov|edu|mil|int|co|uk|de|ru|cn|fr|br|in|jp|"
    r"xyz|info|biz|me|tv|cc|tk|pw|top|club|online|site|app|dev|cloud|"
    r"onion)\b",
    re.IGNORECASE,
)
RE_ONION = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
RE_BASE64 = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")

# Known benign image specification sequences to ignore
BENIGN_IMAGE_SEQUENCES = {
    "CDEFGHIJSTUVWXYZcdefghijstuvwxyz",
    "cdefghijstuvwxyz",
    "CDEFGHIJSTUVWXYZ",
    "sRGB IEC61966-2.1",
    "IEC http://www.iec.ch",
}

RE_SUSPICIOUS_COMMANDS = re.compile(
    r"(?:"
    r"\bpowershell(?:\.exe)?\s+-[a-zA-Z]+|\bpowershell\.exe\b|"
    r"\bcmd(?:\.exe)?\s+/(?:c|k|r)|\bcmd\.exe\b|"
    r"/bin/(?:ba)?sh|\b(?:bash|sh)\s+-[ce]|\b(?:bash|sh)\s+http|"
    r"\bcertutil(?:\.exe)?\s+-[a-zA-Z]+|\bcertutil\.exe\b|"
    r"\bbitsadmin(?:\.exe)?\s+/[a-zA-Z]+|"
    r"\bwget\s+(?:-[a-zA-Z]|http)|\bcurl\s+(?:-[a-zA-Z]|http)|\bcurl\s*\||\bwget\s*\||"
    r"\binvoke-expression|\biex\s*\(|\biex\s+\$|\binvoke-webrequest|\biwr\s+-[a-zA-Z]|"
    r"\beval\s*\(|"
    r"\bexec\s*\(|"
    r"\bbase64_decode\s*\(|"
    r"\bsystem\s*\(|"
    r"\bpassthru\s*\(|"
    r"\bshell_exec\s*\(|"
    r"\bwscript\.shell|"
    r"\brundll32(?:\.exe)?|"
    r"\bregsvr32(?:\.exe)?|"
    r"\bmshta(?:\.exe)?"
    r")",
    re.IGNORECASE,
)

RE_BTC = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")
RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RE_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")


def _extract_ascii_strings(raw_bytes: bytes, min_len: int = 4) -> List[str]:
    pattern = rf"[ -~]{{{min_len},}}"
    return [match.decode("ascii", errors="ignore") for match in re.findall(pattern.encode("ascii"), raw_bytes)]


def _extract_utf16_strings(raw_bytes: bytes, min_len: int = 4) -> List[str]:
    pattern_le = rf"(?:[ -~]\x00){{{min_len},}}"
    pattern_be = rf"(?:\x00[ -~]){{{min_len},}}"

    results = []
    for match in re.findall(pattern_le.encode("ascii"), raw_bytes):
        try:
            results.append(match.decode("utf-16le", errors="ignore"))
        except Exception:
            pass

    for match in re.findall(pattern_be.encode("ascii"), raw_bytes):
        try:
            results.append(match.decode("utf-16be", errors="ignore"))
        except Exception:
            pass

    return results


def _is_valid_ipv4(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        if ip.is_unspecified or ip.is_loopback or ip.is_reserved or ip.is_multicast:
            return False
        if ip_str == "255.255.255.255":
            return False
        return True
    except Exception:
        return False


def _is_valid_base64_blob(b64_str: str) -> bool:
    if len(b64_str) < 20:
        return False

    if any(seq in b64_str for seq in BENIGN_IMAGE_SEQUENCES):
        return False

    # Pad to nearest multiple of 4 so strings captured without trailing '='
    # by the regex are still decodeable.
    padded = b64_str + "=" * ((-len(b64_str)) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
        if len(decoded) < 12:
            return False

        printable_count = sum(1 for b in decoded if 32 <= b <= 126 or b in (9, 10, 13))
        ratio = printable_count / len(decoded)

        if ratio >= 0.60 or decoded.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04", b"{\"", b"<?xml", b"http", b"powershell")):
            return True
        return False
    except Exception:
        return False


def analyze_strings(raw_bytes: bytes, min_len: int = 4, max_samples: int = 100) -> StringsReport:
    report = StringsReport()

    ascii_strings = _extract_ascii_strings(raw_bytes, min_len=min_len)
    utf16_strings = _extract_utf16_strings(raw_bytes, min_len=min_len)

    all_strings = ascii_strings + utf16_strings
    report.total_strings_found = len(all_strings)
    report.extracted_ascii_count = len(ascii_strings)
    report.extracted_utf16_count = len(utf16_strings)

    joined_text = "\n".join(all_strings)

    # 1. IPv4
    raw_ips = RE_IPV4.findall(joined_text)
    valid_ips = sorted(list(set(ip for ip in raw_ips if _is_valid_ipv4(ip))))
    report.iocs_detected["ipv4"] = valid_ips

    # 2. URLs & Onion addresses
    urls = list(set(RE_URL.findall(joined_text)))
    onion_addresses = list(set(RE_ONION.findall(joined_text)))
    all_urls = sorted(list(set(urls + onion_addresses)))
    report.iocs_detected["urls"] = all_urls

    # 3. Stand-alone domains (not already part of a full URL)
    raw_domains = list(set(RE_DOMAIN.findall(joined_text)))
    # Remove domains that are sub-strings of an already-captured URL to avoid
    # duplicates (e.g. "example.com" from "http://example.com/path")
    url_set = set(all_urls)
    standalone_domains = sorted(
        d for d in raw_domains
        if not any(d in u for u in url_set)
        and not d.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".tif", ".tiff", ".bmp"))
    )
    report.iocs_detected["domains"] = standalone_domains

    # 3. Emails
    emails = sorted(list(set(RE_EMAIL.findall(joined_text))))
    valid_emails = [e for e in emails if not e.endswith((".jpg", ".png", ".gif", ".webp", ".tif"))]
    report.iocs_detected["emails"] = valid_emails

    # 4. Base64 Blobs
    b64_candidates = RE_BASE64.findall(joined_text)
    valid_b64 = sorted(list(set(b for b in b64_candidates if _is_valid_base64_blob(b))))[:20]
    report.iocs_detected["base64_blobs"] = valid_b64

    # 5. Shell & Malicious Commands
    shell_matches = sorted(list(set(RE_SUSPICIOUS_COMMANDS.findall(joined_text))))
    report.iocs_detected["shell_commands"] = shell_matches

    # 6. Crypto Wallets
    btc_wallets = RE_BTC.findall(joined_text)
    eth_wallets = RE_ETH.findall(joined_text)
    xmr_wallets = RE_XMR.findall(joined_text)
    all_wallets = sorted(list(set(btc_wallets + eth_wallets + xmr_wallets)))
    report.iocs_detected["crypto_wallets"] = all_wallets

    suspicious = []
    if valid_ips:
        suspicious.append(f"Identified {len(valid_ips)} IPv4 address(es): {', '.join(valid_ips[:5])}")
    if all_urls:
        suspicious.append(f"Identified {len(all_urls)} URL/Onion endpoint(s): {', '.join(all_urls[:5])}")
    if standalone_domains:
        suspicious.append(f"Identified {len(standalone_domains)} standalone domain(s): {', '.join(standalone_domains[:5])}")
    if valid_emails:
        suspicious.append(f"Identified {len(valid_emails)} Email address(es): {', '.join(valid_emails[:5])}")
    if valid_b64:
        suspicious.append(f"Identified {len(valid_b64)} high-entropy Base64 payload blob(s).")
    if shell_matches:
        suspicious.append(f"Identified suspicious shell/execution keyword(s): {', '.join(shell_matches)}")
    if all_wallets:
        suspicious.append(f"Identified cryptocurrency wallet address(es): {', '.join(all_wallets[:3])}")

    report.suspicious_strings = suspicious
    report.sample_strings = all_strings[:max_samples]

    return report
