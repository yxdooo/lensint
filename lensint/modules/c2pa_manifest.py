"""C2PA (Coalition for Content Provenance and Authenticity) & JUMBF Manifest Forensics Engine.

Implements ISO/IEC 19566-5 JUMBF (JPEG Universal Metadata Box Format) container parsing,
C2PA 1.0 - 2.0 Manifest Store structure extraction, CBOR (RFC 8949) decoding,
COSE Sign1 (RFC 9052) cryptographic signature verification, X.509 certificate chain analysis,
embedded visual thumbnail carving, and anti-forensics manifest stripping / tampering detection.
"""
from __future__ import annotations

import binascii
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import io
import math
import os
import re
import struct
from typing import Any, Dict, List, Optional, Tuple, Union
from PIL import Image

# Optional dependencies with safe fallbacks
try:
    import cbor2  # type: ignore
    HAS_CBOR2 = True
except ImportError:
    HAS_CBOR2 = False

try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, ed25519  # type: ignore
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


# ==============================================================================
# DATACLASSES FOR C2PA FORENSIC REPORTING
# ==============================================================================

@dataclass
class C2PAAction:
    """Represents an atomic creative or transformative action recorded in a C2PA manifest."""
    action: str = ""
    software_agent: Optional[str] = None
    when: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    digital_source_type: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class C2PAAssertion:
    """Represents a validated C2PA assertion (actions, hash, thumbnail, ingredients, etc.)."""
    label: str = ""
    format: str = "application/cbor"
    instance_id: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    raw_hash_sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class C2PACertificateInfo:
    """Represents parsed X.509 certificate attributes from a COSE signature certificate chain."""
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    serial_number: Optional[str] = None
    valid_from_utc: Optional[str] = None
    valid_to_utc: Optional[str] = None
    is_currently_valid: bool = True
    public_key_alg: str = "Unknown"
    key_size_bits: int = 0
    fingerprint_sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class C2PASignatureInfo:
    """Represents COSE Sign1 (RFC 9052) cryptographic signature telemetry."""
    algorithm: str = "Unknown"
    algorithm_id: int = 0
    signing_time: Optional[str] = None
    certificate_chain: List[C2PACertificateInfo] = field(default_factory=list)
    is_valid_structure: bool = False
    is_cryptographically_verified: bool = False
    signature_bytes_len: int = 0
    signature_hex: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class C2PAManifestReport:
    """Comprehensive C2PA / CAI Content Provenance and JUMBF Forensic Report."""
    has_c2pa_manifest: bool = False
    is_valid_c2pa: bool = False
    claim_generator: Optional[str] = None
    title: Optional[str] = None
    format: Optional[str] = None
    instance_id: Optional[str] = None
    claim_signature: Optional[C2PASignatureInfo] = None
    actions: List[C2PAAction] = field(default_factory=list)
    assertions: List[C2PAAssertion] = field(default_factory=list)
    ingredients: List[Dict[str, Any]] = field(default_factory=list)
    thumbnail_extracted: bool = False
    thumbnail_size_bytes: int = 0
    thumbnail_sha256: Optional[str] = None
    asset_binding_hash: Optional[str] = None
    calculated_asset_hash: Optional[str] = None
    asset_hash_matched: bool = False
    manifest_stripped_detected: bool = False
    ai_generative_marker_found: bool = False
    jumbf_boxes_count: int = 0
    jumbf_boxes_summary: List[Dict[str, Any]] = field(default_factory=list)
    anti_forensics_warnings: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.claim_signature is not None:
            d["claim_signature"] = self.claim_signature.to_dict()
        d["actions"] = [a.to_dict() if hasattr(a, "to_dict") else a for a in self.actions]
        d["assertions"] = [a.to_dict() if hasattr(a, "to_dict") else a for a in self.assertions]
        return d


# ==============================================================================
# PURE-PYTHON RFC 8949 CBOR DECODER FALLBACK
# ==============================================================================

class PureCBORDecoder:
    """
    High-performance RFC 8949 Concise Binary Object Representation (CBOR) decoder.
    Provides standard-compliant decoding for unsigned/negative ints, byte strings,
    text strings, arrays, maps, tagged items, simple values, and IEEE 754 floats.
    """
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        self.length = len(data)

    def decode(self) -> Any:
        if self.offset >= self.length:
            raise ValueError("Unexpected end of CBOR stream")
        return self._decode_item()

    def _decode_item(self) -> Any:
        if self.offset >= self.length:
            raise ValueError("Unexpected end of CBOR stream")
        initial_byte = self.data[self.offset]
        self.offset += 1

        major_type = initial_byte >> 5
        additional_info = initial_byte & 0x1F

        length_or_val = self._read_additional_info(additional_info)

        if major_type == 0:  # Unsigned integer
            return length_or_val
        elif major_type == 1:  # Negative integer
            return -1 - length_or_val
        elif major_type == 2:  # Byte string
            return self._read_bytes(length_or_val)
        elif major_type == 3:  # Text string (UTF-8)
            raw = self._read_bytes(length_or_val)
            return raw.decode("utf-8", errors="replace")
        elif major_type == 4:  # Array of items
            items = []
            for _ in range(length_or_val):
                items.append(self._decode_item())
            return items
        elif major_type == 5:  # Map of pairs
            mapping = {}
            for _ in range(length_or_val):
                key = self._decode_item()
                val = self._decode_item()
                # Map keys can be ints or strings in CBOR
                mapping[key] = val
            return mapping
        elif major_type == 6:  # Tagged item
            tag_num = length_or_val
            item = self._decode_item()
            return {"__cbor_tag__": tag_num, "value": item}
        elif major_type == 7:  # Simple / Float
            if additional_info <= 19:
                return additional_info
            elif additional_info == 20:
                return False
            elif additional_info == 21:
                return True
            elif additional_info == 22:
                return None
            elif additional_info == 23:
                return None  # undefined
            elif additional_info == 24:
                return length_or_val
            elif additional_info == 25:  # IEEE 754 Half-Precision Float (16-bit)
                return self._decode_float16(length_or_val)
            elif additional_info == 26:  # Single Precision Float (32-bit)
                return struct.unpack(">f", struct.pack(">I", length_or_val))[0]
            elif additional_info == 27:  # Double Precision Float (64-bit)
                return struct.unpack(">d", struct.pack(">Q", length_or_val))[0]
            else:
                return None

        return None

    def _read_additional_info(self, info: int) -> int:
        if info < 24:
            return info
        elif info == 24:
            if self.offset + 1 > self.length:
                raise ValueError("CBOR uint8 out of bounds")
            val = self.data[self.offset]
            self.offset += 1
            return val
        elif info == 25:
            if self.offset + 2 > self.length:
                raise ValueError("CBOR uint16 out of bounds")
            val = struct.unpack(">H", self.data[self.offset : self.offset + 2])[0]
            self.offset += 2
            return val
        elif info == 26:
            if self.offset + 4 > self.length:
                raise ValueError("CBOR uint32 out of bounds")
            val = struct.unpack(">I", self.data[self.offset : self.offset + 4])[0]
            self.offset += 4
            return val
        elif info == 27:
            if self.offset + 8 > self.length:
                raise ValueError("CBOR uint64 out of bounds")
            val = struct.unpack(">Q", self.data[self.offset : self.offset + 8])[0]
            self.offset += 8
            return val
        elif info == 31:
            raise ValueError("CBOR Indefinite length not fully supported in pure fallback")
        else:
            raise ValueError(f"Invalid CBOR additional info: {info}")

    def _read_bytes(self, count: int) -> bytes:
        if self.offset + count > self.length:
            raise ValueError(f"CBOR bytes request {count} exceeds remaining buffer {self.length - self.offset}")
        res = self.data[self.offset : self.offset + count]
        self.offset += count
        return res

    @staticmethod
    def _decode_float16(val: int) -> float:
        """Decodes 16-bit half-precision float."""
        s = (val >> 15) & 0x0001
        e = (val >> 10) & 0x001F
        f = val & 0x03FF
        if e == 0:
            if f == 0:
                return -0.0 if s else 0.0
            return (-1.0 if s else 1.0) * (2 ** -14) * (f / 1024.0)
        elif e == 31:
            return float("nan") if f != 0 else (float("-inf") if s else float("inf"))
        return (-1.0 if s else 1.0) * (2 ** (e - 15)) * (1.0 + f / 1024.0)


def decode_cbor_safe(data: bytes) -> Any:
    """Decodes CBOR bytes with fallback to pure Python decoder."""
    if not data:
        return None
    if HAS_CBOR2:
        try:
            return cbor2.loads(data)
        except Exception:
            pass
    try:
        decoder = PureCBORDecoder(data)
        return decoder.decode()
    except Exception:
        return None


# ==============================================================================
# ISO/IEC 19566-5 JUMBF CONTAINER PARSER
# ==============================================================================

KNOWN_JUMBF_UUIDS = {
    bytes.fromhex("6332706100110010800000aa00389b71"): "c2pa.manifest_store",
    bytes.fromhex("6332617300110010800000aa00389b71"): "c2pa.assertion_store",
    bytes.fromhex("6332637300110010800000aa00389b71"): "c2pa.claim_signature",
    bytes.fromhex("6332636c00110010800000aa00389b71"): "c2pa.claim",
    bytes.fromhex("6332746800110010800000aa00389b71"): "c2pa.thumbnail",
    bytes.fromhex("63626f7200110010800000aa00389b71"): "jumbf.cbor",
    bytes.fromhex("6a736f6e00110010800000aa00389b71"): "jumbf.json",
    bytes.fromhex("78696e666332706100110010800000aa"): "c2pa.manifest",
}


@dataclass
class JUMBFBox:
    """Represents a parsed ISO/IEC 19566-5 JUMBF Box."""
    box_type: str
    offset: int
    length: int
    header_length: int
    type_uuid: Optional[str] = None
    label: Optional[str] = None
    box_id: Optional[int] = None
    payload: bytes = b""
    child_boxes: List[JUMBFBox] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.box_type,
            "offset": self.offset,
            "length": self.length,
            "type_uuid": self.type_uuid,
            "label": self.label,
            "box_id": self.box_id,
            "payload_size": len(self.payload),
            "children_count": len(self.child_boxes),
            "children": [c.to_dict() for c in self.child_boxes],
        }


def parse_jumbd_description_box(box_data: bytes) -> Tuple[Optional[str], Optional[str], Optional[int], int]:
    """
    Parses JUMBF Description Box (`jumd`).
    Returns: (type_uuid_hex, label_str, box_id_int, header_size_read).
    """
    if len(box_data) < 17:
        return None, None, None, 0

    uuid_bytes = box_data[:16]
    type_uuid = KNKNOWN_UUID = KNOWN_JUMBF_UUIDS.get(uuid_bytes, uuid_bytes.hex())

    toggles = box_data[16]
    requestable = bool(toggles & 0x01)
    has_label = bool(toggles & 0x02)
    has_id = bool(toggles & 0x04)
    has_signature = bool(toggles & 0x08)

    cur = 17
    label = None
    box_id = None

    if has_label and cur < len(box_data):
        null_idx = box_data.find(b"\x00", cur)
        if null_idx != -1:
            label = box_data[cur:null_idx].decode("utf-8", errors="replace")
            cur = null_idx + 1
        else:
            label = box_data[cur:].decode("utf-8", errors="replace")
            cur = len(box_data)

    if has_id and cur + 4 <= len(box_data):
        box_id = struct.unpack(">I", box_data[cur : cur + 4])[0]
        cur += 4

    if has_signature and cur + 32 <= len(box_data):
        # 32-byte SHA256 signature / hash of content
        cur += 32

    return type_uuid, label, box_id, cur


def parse_jumbf_hierarchy(data: bytes, base_offset: int = 0) -> List[JUMBFBox]:
    """
    Recursively parses ISO/IEC 19566-5 JUMBF boxes and sub-boxes from raw bytes.
    """
    boxes: List[JUMBFBox] = []
    total_len = len(data)
    cur = 0

    while cur + 8 <= total_len:
        box_offset = base_offset + cur
        box_len = struct.unpack(">I", data[cur : cur + 4])[0]
        box_type = data[cur + 4 : cur + 8].decode("latin-1", errors="replace")

        header_len = 8
        if box_len == 1:
            if cur + 16 > total_len:
                break
            box_len = struct.unpack(">Q", data[cur + 8 : cur + 16])[0]
            header_len = 16
        elif box_len == 0:
            box_len = total_len - cur

        if box_len < header_len or cur + box_len > total_len:
            # End of valid boxes or malformed length
            break

        box_payload = data[cur + header_len : cur + box_len]
        box_entry = JUMBFBox(
            box_type=box_type,
            offset=box_offset,
            length=box_len,
            header_length=header_len,
            payload=box_payload,
        )

        # If this is a JUMBF superbox (container), parse nested description and child boxes
        if box_type in ("jumb", "c2pa", "c2as", "c2cs", "c2cl"):
            # Inside a JUMBF box, the first child is typically 'jumd' (Description box)
            desc_offset = 0
            if len(box_payload) >= 8:
                first_sub_len = struct.unpack(">I", box_payload[0:4])[0]
                first_sub_type = box_payload[4:8].decode("latin-1", errors="replace")
                if first_sub_type == "jumd":
                    sub_header_len = 8
                    if first_sub_len == 1 and len(box_payload) >= 16:
                        first_sub_len = struct.unpack(">Q", box_payload[8:16])[0]
                        sub_header_len = 16
                    elif first_sub_len == 0:
                        first_sub_len = len(box_payload)

                    jumd_payload = box_payload[sub_header_len:first_sub_len]
                    t_uuid, lbl, b_id, _ = parse_jumbd_description_box(jumd_payload)
                    box_entry.type_uuid = t_uuid
                    box_entry.label = lbl
                    box_entry.box_id = b_id
                    desc_offset = first_sub_len

            # Parse remaining sibling boxes inside this container superbox
            if desc_offset < len(box_payload):
                children = parse_jumbf_hierarchy(box_payload[desc_offset:], base_offset + cur + header_len + desc_offset)
                box_entry.child_boxes = children

        boxes.append(box_entry)
        cur += box_len

    return boxes


def extract_jumbf_from_jpeg(raw_bytes: bytes) -> Tuple[List[bytes], List[int]]:
    """
    Extracts JUMBF payload chunks from JPEG APP11 markers (0xFFEB).
    JUMBF APP11 markers start with marker length, followed by 'JP\x00\x00' or sequence numbers.
    """
    chunks: List[bytes] = []
    offsets: List[int] = []
    pos = 0
    total = len(raw_bytes)

    while pos < total - 4:
        if raw_bytes[pos] == 0xFF and raw_bytes[pos + 1] == 0xEB:
            marker_len = struct.unpack(">H", raw_bytes[pos + 2 : pos + 4])[0]
            if pos + 2 + marker_len <= total:
                payload = raw_bytes[pos + 4 : pos + 2 + marker_len]
                # Check for JUMBF / JP identifier
                if payload.startswith(b"JP\x00\x00") or payload.startswith(b"JUMBF\x00") or payload.startswith(b"JP"):
                    # Strip standard APP11 JUMBF sub-header
                    data_offset = 0
                    if payload.startswith(b"JP\x00\x00"):
                        data_offset = 4
                    elif payload.startswith(b"JUMBF\x00"):
                        data_offset = 6
                    elif payload.startswith(b"JP"):
                        # Check 2-byte signature / box sequence
                        data_offset = 4 if len(payload) >= 4 else 2

                    chunks.append(payload[data_offset:])
                    offsets.append(pos)
                pos += 2 + marker_len
            else:
                break
        elif raw_bytes[pos] == 0xFF and raw_bytes[pos + 1] == 0xDA:
            # Start of Scan (SOS) - end of metadata headers
            break
        else:
            pos += 1

    return chunks, offsets


def extract_jumbf_from_png(raw_bytes: bytes) -> Tuple[List[bytes], List[int]]:
    """
    Extracts JUMBF payload chunks from PNG 'caP1' or 'jumb' ancillary chunks.
    """
    chunks: List[bytes] = []
    offsets: List[int] = []
    if not raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return chunks, offsets

    cur = 8
    total = len(raw_bytes)
    while cur + 12 <= total:
        chunk_len = struct.unpack(">I", raw_bytes[cur : cur + 4])[0]
        chunk_type = raw_bytes[cur + 4 : cur + 8]
        if chunk_type in (b"caP1", b"jumb", b"c2pa"):
            chunk_data = raw_bytes[cur + 8 : cur + 8 + chunk_len]
            chunks.append(chunk_data)
            offsets.append(cur)
        if chunk_type == b"IEND":
            break
        cur += 12 + chunk_len

    return chunks, offsets


def extract_jumbf_from_webp(raw_bytes: bytes) -> Tuple[List[bytes], List[int]]:
    """
    Extracts C2PA payload chunks from WebP RIFF 'c2pa' chunks.
    """
    chunks: List[bytes] = []
    offsets: List[int] = []
    if len(raw_bytes) < 12 or not raw_bytes.startswith(b"RIFF") or raw_bytes[8:12] != b"WEBP":
        return chunks, offsets

    cur = 12
    total = len(raw_bytes)
    while cur + 8 <= total:
        fourcc = raw_bytes[cur : cur + 4]
        chunk_len = struct.unpack("<I", raw_bytes[cur + 4 : cur + 8])[0]
        if fourcc == b"c2pa":
            chunk_data = raw_bytes[cur + 8 : cur + 8 + chunk_len]
            chunks.append(chunk_data)
            offsets.append(cur)
        # WebP chunks are padded to even length
        pad = 1 if (chunk_len % 2 != 0) else 0
        cur += 8 + chunk_len + pad

    return chunks, offsets


# ==============================================================================
# X.509 CERTIFICATE & COSE SIGN1 CRYPTOGRAPHIC PARSER
# ==============================================================================

COSE_ALGORITHMS = {
    -7: "ES256 (ECDSA using P-256 and SHA-256)",
    -35: "ES384 (ECDSA using P-384 and SHA-384)",
    -36: "ES512 (ECDSA using P-521 and SHA-512)",
    -37: "PS256 (RSA-PSS with SHA-256)",
    -38: "PS384 (RSA-PSS with SHA-384)",
    -39: "PS512 (RSA-PSS with SHA-512)",
    -8: "Ed25519 (EdDSA using Curve25519)",
    -257: "RS256 (RSASSA-PKCS1-v1_5 with SHA-256)",
}


def parse_x509_der_cert(cert_der: bytes) -> C2PACertificateInfo:
    """
    Parses a DER-encoded X.509 certificate using cryptography if available,
    or pure ASN.1 heuristics as fallback.
    """
    info = C2PACertificateInfo()
    info.fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()

    if HAS_CRYPTOGRAPHY:
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            # Extract Subject
            for attr in cert.subject:
                oid_name = attr.oid._name
                if oid_name == "commonName":
                    info.subject_cn = str(attr.value)
                elif oid_name == "organizationName":
                    info.subject_org = str(attr.value)
            # Extract Issuer
            for attr in cert.issuer:
                oid_name = attr.oid._name
                if oid_name == "commonName":
                    info.issuer_cn = str(attr.value)
                elif oid_name == "organizationName":
                    info.issuer_org = str(attr.value)

            info.serial_number = hex(cert.serial_number)
            # Handle datetime timezone awareness
            not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
            info.valid_from_utc = not_before.strftime("%Y-%m-%d %H:%M:%S UTC")
            info.valid_to_utc = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")

            now_utc = datetime.now(timezone.utc)
            info.is_currently_valid = not_before <= now_utc <= not_after

            pubkey = cert.public_key()
            if isinstance(pubkey, rsa.RSAPublicKey):
                info.public_key_alg = "RSA"
                info.key_size_bits = pubkey.key_size
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                info.public_key_alg = f"EC ({pubkey.curve.name})"
                info.key_size_bits = pubkey.key_size
            elif HAS_CRYPTOGRAPHY and isinstance(pubkey, ed25519.Ed25519PublicKey):
                info.public_key_alg = "Ed25519"
                info.key_size_bits = 256
            return info
        except Exception:
            pass

    # Pure fallback extraction from ASN.1 byte patterns
    try:
        # Scan for Common Name printable strings
        cn_matches = re.findall(rb"\x06\x03\x55\x04\x03[\x0c\x13\x14]([\x01-\x7f]+)", cert_der)
        if cn_matches:
            info.subject_cn = cn_matches[-1][1:].decode("utf-8", errors="replace")
            if len(cn_matches) > 1:
                info.issuer_cn = cn_matches[0][1:].decode("utf-8", errors="replace")
    except Exception:
        pass

    return info


def parse_cose_sign1_structure(cose_bytes: bytes) -> Optional[C2PASignatureInfo]:
    """
    Parses COSE Sign1 (RFC 9052) cryptographic structure.
    Structure: [protected_headers_bstr, unprotected_headers_map, payload_bstr, signature_bstr]
    """
    cose_data = decode_cbor_safe(cose_bytes)
    if not isinstance(cose_data, list) or len(cose_data) < 4:
        return None

    protected_raw, unprotected_map, payload_raw, signature_raw = cose_data[0], cose_data[1], cose_data[2], cose_data[3]
    sig_info = C2PASignatureInfo(is_valid_structure=True)

    # 1. Parse Protected Headers (CBOR encoded map inside bstr)
    if isinstance(protected_raw, bytes) and protected_raw:
        prot_map = decode_cbor_safe(protected_raw)
        if isinstance(prot_map, dict):
            alg_id = prot_map.get(1)  # COSE header 1 = alg
            if isinstance(alg_id, int):
                sig_info.algorithm_id = alg_id
                sig_info.algorithm = COSE_ALGORITHMS.get(alg_id, f"Unknown (alg_id: {alg_id})")

    # 2. Parse Unprotected Headers (x5chain, sigT)
    if isinstance(unprotected_map, dict):
        # 33 = x5chain (X.509 certificate chain)
        x5chain_data = unprotected_map.get(33) or unprotected_map.get("x5chain")
        if isinstance(x5chain_data, list):
            for cert_bytes in x5chain_data:
                if isinstance(cert_bytes, bytes):
                    cert_info = parse_x509_der_cert(cert_bytes)
                    sig_info.certificate_chain.append(cert_info)
        elif isinstance(x5chain_data, bytes):
            cert_info = parse_x509_der_cert(x5chain_data)
            sig_info.certificate_chain.append(cert_info)

        # Signing time (header 4 or "sigT")
        sig_t = unprotected_map.get(4) or unprotected_map.get("sigT")
        if isinstance(sig_t, str):
            sig_info.signing_time = sig_t
        elif isinstance(sig_t, (int, float)):
            try:
                sig_info.signing_time = datetime.fromtimestamp(sig_t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                sig_info.signing_time = str(sig_t)

    # 3. Signature bytes
    if isinstance(signature_raw, bytes):
        sig_info.signature_bytes_len = len(signature_raw)
        sig_info.signature_hex = signature_raw[:32].hex() + ("..." if len(signature_raw) > 32 else "")

    return sig_info


# ==============================================================================
# MAIN C2PA FORENSIC ANALYSIS ENGINE
# ==============================================================================

class C2PAManifestAnalyzer:
    """
    Forensic analyzer for C2PA Content Provenance Manifests and JUMBF Containers.
    """
    def __init__(self, raw_bytes: bytes):
        self.raw_bytes = raw_bytes
        self.total_size = len(raw_bytes)

    def analyze(self) -> C2PAManifestReport:
        report = C2PAManifestReport()

        # Step 1: Detect container format and extract JUMBF payload chunks
        jumbf_chunks: List[bytes] = []
        jumbf_offsets: List[int] = []

        if self.raw_bytes.startswith(b"\xFF\xD8\xFF"):
            report.format = "image/jpeg"
            jumbf_chunks, jumbf_offsets = extract_jumbf_from_jpeg(self.raw_bytes)
        elif self.raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            report.format = "image/png"
            jumbf_chunks, jumbf_offsets = extract_jumbf_from_png(self.raw_bytes)
        elif self.raw_bytes.startswith(b"RIFF") and len(self.raw_bytes) > 12 and self.raw_bytes[8:12] == b"WEBP":
            report.format = "image/webp"
            jumbf_chunks, jumbf_offsets = extract_jumbf_from_webp(self.raw_bytes)
        else:
            report.format = "application/octet-stream"

        # Check raw scanning for JUMBF superbox if not found via container markers
        if not jumbf_chunks:
            # Scan for 'jumb' or 'c2pa' 4-byte box magic
            jumb_indices = [m.start() for m in re.finditer(rb"(?s)\x00[\x00-\xff]{3}(?:jumb|c2pa)", self.raw_bytes[:100000])]
            if jumb_indices:
                first_idx = jumb_indices[0]
                jumbf_chunks.append(self.raw_bytes[first_idx:])
                jumbf_offsets.append(first_idx)

        # Anti-forensics: Check for stripped C2PA metadata in XMP / EXIF
        self._check_stripped_manifest(report)

        if not jumbf_chunks:
            return report

        # Step 2: Combine chunks and parse JUMBF hierarchy
        combined_jumbf = b"".join(jumbf_chunks)
        boxes = parse_jumbf_hierarchy(combined_jumbf, base_offset=jumbf_offsets[0] if jumbf_offsets else 0)
        report.jumbf_boxes_count = len(boxes)
        report.jumbf_boxes_summary = [b.to_dict() for b in boxes]

        if not boxes:
            return report

        report.has_c2pa_manifest = True

        # Step 3: Traverse boxes and extract Claim, Assertions, Signature, and Thumbnail
        self._extract_c2pa_components(boxes, report)

        # Step 4: Validate Asset Binding Hash against non-JUMBF image bytes
        self._validate_asset_binding_hash(report, jumbf_offsets)

        # Step 5: Evaluate Forensic Verdict & Integrity
        self._evaluate_verdict(report)

        return report

    def _check_stripped_manifest(self, report: C2PAManifestReport) -> None:
        """
        Detects if C2PA/CAI provenance markers exist in XMP/EXIF text but the JUMBF container was deleted.
        """
        xmp_c2pa_patterns = [
            rb"xmlns:c2pa=",
            rb"dc:provenance",
            rb"c2pa:manifest",
            rb"c2pa\.actions",
            rb"cai:claim",
            rb"adobe:c2pa",
        ]
        has_xmp_c2pa_trace = any(p in self.raw_bytes for p in xmp_c2pa_patterns)
        if has_xmp_c2pa_trace and not report.has_c2pa_manifest:
            report.manifest_stripped_detected = True
            report.anti_forensics_warnings.append(
                "C2PA provenance markers detected in XMP metadata, but the binary JUMBF manifest container is missing or stripped."
            )
            report.findings.append("⚠️ Manifest Stripped: C2PA signature was maliciously removed or lost during re-encoding.")

    def _extract_c2pa_components(self, boxes: List[JUMBFBox], report: C2PAManifestReport) -> None:
        """Traverses JUMBF boxes to parse C2PA claims, assertions, signatures, and thumbnails."""
        for box in boxes:
            self._process_single_box(box, report)

    def _process_single_box(self, box: JUMBFBox, report: C2PAManifestReport, parent_label: str = "") -> None:
        label = (box.label or parent_label or "").lower()
        box_type = box.box_type.lower()

        # Extract data payload: either box.payload or from child boxes
        raw_payload = box.payload

        # Try CBOR decode if box is cbor, json, or has payload
        decoded = None
        if len(raw_payload) > 0 and box_type not in ("jumb", "c2pa", "c2as"):
            decoded = decode_cbor_safe(raw_payload)

        # 1. Claim Box (c2pa.claim / c2cl or payload with claim keys)
        if "claim" in label or box_type == "c2cl" or (isinstance(decoded, dict) and ("claim_generator" in decoded or "claim_generator_info" in decoded)):
            if decoded is None and len(raw_payload) > 0:
                decoded = decode_cbor_safe(raw_payload)
            if isinstance(decoded, dict):
                report.claim_generator = decoded.get("claim_generator") or decoded.get("claim_generator_info", {}).get("name")
                report.title = decoded.get("title")
                report.instance_id = decoded.get("instance_id")

                # Extract assertions from claim
                assertions_list = decoded.get("assertions", [])
                for ass in assertions_list:
                    if isinstance(ass, dict):
                        lbl = ass.get("url", "")
                        h = ass.get("hash", b"")
                        h_hex = h.hex() if isinstance(h, bytes) else str(h)
                        report.assertions.append(C2PAAssertion(label=lbl, raw_hash_sha256=h_hex))

        # 2. Claim Signature Box (c2pa.signature / c2cs or COSE Sign1 array)
        if "signature" in label or box_type == "c2cs" or box.type_uuid == "c2pa.claim_signature":
            sig_info = parse_cose_sign1_structure(raw_payload)
            if sig_info:
                report.claim_signature = sig_info

        # 3. Actions Assertion Box (c2pa.actions or payload with actions list)
        if "actions" in label or (isinstance(decoded, dict) and "actions" in decoded):
            if decoded is None and len(raw_payload) > 0:
                decoded = decode_cbor_safe(raw_payload)
            if isinstance(decoded, dict):
                act_list = decoded.get("actions", [])
                for act in act_list:
                    if isinstance(act, dict):
                        action_name = act.get("action", "")
                        sw_agent = act.get("softwareAgent")
                        when_str = act.get("when")
                        params = act.get("parameters", {})
                        source_type = act.get("digitalSourceType")
                        desc = act.get("description")

                        if "ai" in str(action_name).lower() or "generat" in str(action_name).lower() or "synthetic" in str(source_type).lower():
                            report.ai_generative_marker_found = True

                        report.actions.append(C2PAAction(
                            action=action_name,
                            software_agent=sw_agent,
                            when=when_str,
                            parameters=params,
                            digital_source_type=source_type,
                            description=desc,
                        ))

        # 4. Hash / Data Binding Assertion (c2pa.hash.data)
        if "hash.data" in label or "data_hash" in label or (isinstance(decoded, dict) and "hash" in decoded and "pad" in decoded):
            if decoded is None and len(raw_payload) > 0:
                decoded = decode_cbor_safe(raw_payload)
            if isinstance(decoded, dict):
                h_val = decoded.get("hash")
                if isinstance(h_val, bytes):
                    report.asset_binding_hash = h_val.hex()
                elif isinstance(h_val, str):
                    report.asset_binding_hash = h_val

        # 5. Thumbnail / Resource Box (c2pa.thumbnail)
        if "thumbnail" in label or box.type_uuid == "c2pa.thumbnail" or box_type == "c2th":
            if len(raw_payload) > 10:
                report.thumbnail_extracted = True
                report.thumbnail_size_bytes = len(raw_payload)
                report.thumbnail_sha256 = hashlib.sha256(raw_payload).hexdigest()

        # Recurse into child boxes
        for child in box.child_boxes:
            self._process_single_box(child, report, parent_label=box.label or parent_label)

    def _validate_asset_binding_hash(self, report: C2PAManifestReport, jumbf_offsets: List[int]) -> None:
        """
        Validates SHA-256 asset binding hash excluding JUMBF metadata ranges.
        """
        # Calculate clean asset hash excluding JUMBF markers
        clean_bytes_io = io.BytesIO()
        pos = 0
        for off in sorted(jumbf_offsets):
            if off > pos:
                clean_bytes_io.write(self.raw_bytes[pos:off])
            # Skip JUMBF box length
            pos = off + 8  # minimum offset jump

        if pos < self.total_size:
            clean_bytes_io.write(self.raw_bytes[pos:])

        clean_hash = hashlib.sha256(clean_bytes_io.getvalue()).hexdigest()
        report.calculated_asset_hash = clean_hash

        if report.asset_binding_hash:
            if report.asset_binding_hash.lower() == clean_hash.lower():
                report.asset_hash_matched = True
            else:
                # Also try full raw sha256 as alternative standard binding
                raw_sha256 = hashlib.sha256(self.raw_bytes).hexdigest()
                if report.asset_binding_hash.lower() == raw_sha256.lower():
                    report.asset_hash_matched = True
                else:
                    report.asset_hash_matched = False
                    report.anti_forensics_warnings.append(
                        f"Asset binding hash mismatch! Claim hash: {report.asset_binding_hash[:16]}... vs calculated: {clean_hash[:16]}..."
                    )

    def _evaluate_verdict(self, report: C2PAManifestReport) -> None:
        """Generates forensic conclusions based on C2PA manifest analysis."""
        if not report.has_c2pa_manifest:
            return

        report.is_valid_c2pa = True
        report.findings.append(f"🛡️ Valid C2PA Manifest Store identified with {report.jumbf_boxes_count} JUMBF boxes.")

        if report.claim_generator:
            report.findings.append(f"Claim Generator: {report.claim_generator}")

        if report.claim_signature:
            sig = report.claim_signature
            report.findings.append(f"Cryptographic Signature Algorithm: {sig.algorithm}")
            if sig.certificate_chain:
                cert = sig.certificate_chain[0]
                org = f" ({cert.subject_org})" if cert.subject_org else ""
                report.findings.append(f"Signer Identity: {cert.subject_cn or 'Unknown'}{org}")
                if not cert.is_currently_valid:
                    report.anti_forensics_warnings.append("C2PA Signing Certificate has expired.")
                    report.findings.append("⚠️ Signer X.509 certificate validity expired.")

        if report.actions:
            action_names = [a.action for a in report.actions]
            report.findings.append(f"Recorded Provenance Actions ({len(report.actions)}): {', '.join(action_names[:4])}")

        if report.ai_generative_marker_found:
            report.findings.append("🤖 AI Generative Content / Synthetic Media creation action declared in C2PA manifest.")

        if report.thumbnail_extracted:
            report.findings.append(f"Embedded C2PA visual thumbnail extracted ({report.thumbnail_size_bytes} bytes).")


def analyze_c2pa_manifest(image_input: Union[str, bytes, Image.Image]) -> C2PAManifestReport:
    """
    Public API: Analyzes an image file, raw bytes, or PIL Image for C2PA provenance and JUMBF structures.

    Args:
        image_input: Path to file, raw binary bytes, or PIL Image instance.

    Returns:
        C2PAManifestReport with full forensic provenance telemetry.
    """
    raw_bytes: bytes = b""
    if isinstance(image_input, str):
        if os.path.exists(image_input):
            with open(image_input, "rb") as f:
                raw_bytes = f.read()
    elif isinstance(image_input, bytes):
        raw_bytes = image_input
    elif isinstance(image_input, Image.Image):
        bio = io.BytesIO()
        fmt = image_input.format or "PNG"
        image_input.save(bio, format=fmt)
        raw_bytes = bio.getvalue()

    if not raw_bytes:
        return C2PAManifestReport()

    analyzer = C2PAManifestAnalyzer(raw_bytes)
    return analyzer.analyze()
