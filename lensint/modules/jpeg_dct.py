# Pure-Python JPEG Baseline DCT Coefficient Extractor
# Supports only SOF0 (Baseline Sequential DCT).
# Progressive (FFC2) and Arithmetic-coded JPEG are rejected.
from __future__ import annotations
import struct
from typing import Dict, List, Optional, Tuple


class _BitReader:
    __slots__ = ("_data", "_pos", "_bits", "_nbits", "exhausted")

    def __init__(self, data: bytes) -> None:
        self._data = data; self._pos = 0
        self._bits = 0; self._nbits = 0; self.exhausted = False

    def read_bit(self) -> int:
        if self._nbits == 0:
            self._fill_byte()
        self._nbits -= 1
        return (self._bits >> self._nbits) & 1

    def read_bits(self, n: int) -> int:
        val = 0
        for _ in range(n):
            val = (val << 1) | self.read_bit()
        return val

    def _fill_byte(self) -> None:
        if self._pos >= len(self._data):
            self.exhausted = True; self._bits = 0; self._nbits = 8; return
        byte = self._data[self._pos]; self._pos += 1
        if byte == 0xFF:
            if self._pos >= len(self._data):
                self.exhausted = True; self._bits = 0; self._nbits = 8; return
            nb = self._data[self._pos]; self._pos += 1
            if nb == 0x00:
                pass  # byte stuffing: FF 00 -> FF
            elif 0xD0 <= nb <= 0xD7:
                self._fill_byte(); return  # restart marker
            else:
                self.exhausted = True; self._bits = 0; self._nbits = 8; return
        self._bits = (self._bits << 8) | byte; self._nbits += 8


def _build_huffman_table(bits: List[int], huffvals: List[int]) -> Dict:
    table: Dict[Tuple[int, int], int] = {}
    code = 0; vi = 0
    for length in range(1, 17):
        for _ in range(bits[length - 1]):
            if vi < len(huffvals):
                table[(length, code)] = huffvals[vi]; vi += 1
            code += 1
        code <<= 1
    return table


def _huffman_decode(reader: _BitReader, table: Dict) -> int:
    code = 0
    for length in range(1, 17):
        code = (code << 1) | reader.read_bit()
        sym = table.get((length, code))
        if sym is not None:
            return sym
        if reader.exhausted:
            return 0
    return 0


def _read_amplitude(reader: _BitReader, category: int) -> int:
    if category == 0:
        return 0
    raw = reader.read_bits(category)
    if raw < (1 << (category - 1)):
        raw -= (1 << category) - 1
    return raw


def _decode_block(reader: _BitReader, dc_table: Dict, ac_table: Dict, prev_dc: int):
    coeffs = [0] * 64
    cat = _huffman_decode(reader, dc_table)
    diff = _read_amplitude(reader, cat)
    dc = prev_dc + diff; coeffs[0] = dc
    k = 1
    while k < 64 and not reader.exhausted:
        rs = _huffman_decode(reader, ac_table)
        if rs == 0x00:
            break
        elif rs == 0xF0:
            k += 16
        else:
            run = (rs >> 4) & 0xF; cat2 = rs & 0xF
            k += run
            if k < 64:
                if cat2 > 0:
                    coeffs[k] = _read_amplitude(reader, cat2)
                k += 1
    return coeffs, dc


class JPEGDCTExtractor:
    """Parse a Baseline JPEG (SOF0) and extract all quantized DCT coefficients."""

    def __init__(self, raw_bytes: bytes) -> None:
        self._data = raw_bytes; self._pos = 0
        self.dc_tables: Dict[int, Dict] = {}
        self.ac_tables: Dict[int, Dict] = {}
        self.quant_tables: Dict[int, List[int]] = {}
        self.components: List[Dict] = []
        self.image_width = 0; self.image_height = 0
        self._coefficients: List[List[int]] = []

    def _read_marker(self) -> Optional[int]:
        while self._pos + 1 < len(self._data):
            if self._data[self._pos] == 0xFF:
                m = self._data[self._pos + 1]
                if m not in (0x00, 0xFF):
                    self._pos += 2; return m
            self._pos += 1
        return None

    def _read_uint16(self) -> int:
        if self._pos + 2 > len(self._data): return 0
        v = struct.unpack(">H", self._data[self._pos:self._pos + 2])[0]
        self._pos += 2; return v

    def _read_byte(self) -> int:
        v = self._data[self._pos]; self._pos += 1; return v

    def _parse_dht(self) -> None:
        length = self._read_uint16() - 2; end = self._pos + length
        while self._pos + 17 <= end:
            tc_th = self._read_byte()
            tc = (tc_th >> 4) & 0xF; th = tc_th & 0xF
            bits = list(self._data[self._pos:self._pos + 16]); self._pos += 16
            ns = sum(bits)
            hv = list(self._data[self._pos:self._pos + ns]); self._pos += ns
            t = _build_huffman_table(bits, hv)
            if tc == 0:
                self.dc_tables[th] = t
            else:
                self.ac_tables[th] = t
        self._pos = end

    def _parse_dqt(self) -> None:
        length = self._read_uint16() - 2; end = self._pos + length
        while self._pos + 1 <= end:
            pq_tq = self._read_byte()
            pq = (pq_tq >> 4) & 0xF; tq = pq_tq & 0xF
            if pq == 0:
                if self._pos + 64 > end: break
                vals = list(self._data[self._pos:self._pos + 64]); self._pos += 64
            else:
                if self._pos + 128 > end: break
                vals = list(struct.unpack(">64H", self._data[self._pos:self._pos + 128]))
                self._pos += 128
            self.quant_tables[tq] = vals
        self._pos = end

    def _parse_sof0(self) -> None:
        self._read_uint16(); self._read_byte()
        self.image_height = self._read_uint16(); self.image_width = self._read_uint16()
        nc = self._read_byte(); self.components = []
        for _ in range(nc):
            cid = self._read_byte(); sf = self._read_byte(); qt = self._read_byte()
            self.components.append({
                "id": cid, "h_factor": (sf >> 4) & 0xF, "v_factor": sf & 0xF,
                "qt_id": qt, "dc_table": 0, "ac_table": 0, "prev_dc": 0,
            })

    def _parse_sos(self) -> bytes:
        self._read_uint16(); nc = self._read_byte()
        for _ in range(nc):
            cs = self._read_byte(); td_ta = self._read_byte()
            td = (td_ta >> 4) & 0xF; ta = td_ta & 0xF
            for c in self.components:
                if c["id"] == cs:
                    c["dc_table"] = td; c["ac_table"] = ta; break
        self._pos += 3  # Ss, Se, Ah/Al
        scan = bytearray()
        while self._pos < len(self._data) - 1:
            b = self._data[self._pos]; scan.append(b); self._pos += 1
            if b == 0xFF:
                nb = self._data[self._pos]
                if nb == 0x00:
                    scan.append(nb); self._pos += 1
                elif 0xD0 <= nb <= 0xD7:
                    scan.append(nb); self._pos += 1
                else:
                    self._pos -= 1; scan.pop(); break
        return bytes(scan)

    def _decode_scan(self, scan_data: bytes) -> None:
        if not self.components: return
        max_h = max(c["h_factor"] for c in self.components) or 1
        max_v = max(c["v_factor"] for c in self.components) or 1
        n_mcu_x = (self.image_width + max_h * 8 - 1) // (max_h * 8)
        n_mcu_y = (self.image_height + max_v * 8 - 1) // (max_v * 8)
        reader = _BitReader(scan_data)
        try:
            for _ in range(n_mcu_y):
                for _ in range(n_mcu_x):
                    if reader.exhausted: return
                    for comp in self.components:
                        dc_t = self.dc_tables.get(comp["dc_table"], {})
                        ac_t = self.ac_tables.get(comp["ac_table"], {})
                        for _ in range(comp["h_factor"] * comp["v_factor"]):
                            block, ndc = _decode_block(reader, dc_t, ac_t, comp["prev_dc"])
                            comp["prev_dc"] = ndc
                            self._coefficients.append(block)
        except Exception:
            pass

    def extract(self) -> List[List[int]]:
        """Parse JPEG; return list of 64-int blocks (index 0=DC, 1-63=AC)."""
        if len(self._data) < 4 or self._data[:2] != b"\xFF\xD8":
            return []
        self._pos = 2
        try:
            while True:
                m = self._read_marker()
                if m is None: break
                if m in (0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
                         0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xFE):
                    self._pos += self._read_uint16() - 2
                elif m == 0xDB: self._parse_dqt()
                elif m == 0xC4: self._parse_dht()
                elif m == 0xC0: self._parse_sof0()
                elif m in (0xC1, 0xC2, 0xC3, 0xC9, 0xCA, 0xCB):
                    return []  # Not baseline DCT
                elif m == 0xDA:
                    self._decode_scan(self._parse_sos()); break
                elif m == 0xD9: break
                elif m == 0xDD: self._pos += 4
                else:
                    if self._pos + 2 <= len(self._data):
                        self._pos += max(0, self._read_uint16() - 2)
        except Exception:
            pass
        return self._coefficients


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_jpeg_dct_coefficients(raw_bytes: bytes) -> List[List[int]]:
    """Extract quantized DCT coefficient blocks from a Baseline JPEG.

    Returns list of 64-int lists (one per 8x8 block). Returns [] on failure.
    """
    return JPEGDCTExtractor(raw_bytes).extract()


def get_nonzero_ac_coefficients(raw_bytes: bytes) -> List[int]:
    """Return all non-zero AC coefficients (the steganography carrier set)."""
    result: List[int] = []
    for block in parse_jpeg_dct_coefficients(raw_bytes):
        for i in range(1, 64):
            if block[i] != 0:
                result.append(block[i])
    return result


def estimate_jsteg_payload(raw_bytes: bytes) -> Dict:
    """Attempt JSteg payload detection via real DCT coefficient LSBs.

    JSteg: embed 1 bit per non-zero, non-+-1 AC coefficient (LSB).
    Reads first 8 bytes to detect known file signatures.
    """
    nonzero_ac = get_nonzero_ac_coefficients(raw_bytes)
    carrier = [c for c in nonzero_ac if c not in (1, -1)]
    cap_bits = len(carrier); cap_bytes = cap_bits // 8
    result: Dict = {
        "coefficients_analyzed": len(nonzero_ac),
        "carrier_coefficients": len(carrier),
        "capacity_bits": cap_bits,
        "capacity_bytes": cap_bytes,
        "first_bytes_hex": None,
        "detected_format": None,
        "status": "NO_CARRIER" if cap_bits < 8 else "ANALYZED",
    }
    if cap_bits >= 64:
        bits = [(abs(c) & 1) for c in carrier[:64]]
        extracted = bytearray()
        for i in range(0, 64, 8):
            bv = 0
            for b in bits[i:i + 8]: bv = (bv << 1) | b
            extracted.append(bv)
        result["first_bytes_hex"] = extracted.hex(" ")
        sig = bytes(extracted)
        if sig[:4] == b"\x89PNG": result["detected_format"] = "PNG"; result["status"] = "PAYLOAD_DETECTED"
        elif sig[:2] == b"\xFF\xD8": result["detected_format"] = "JPEG"; result["status"] = "PAYLOAD_DETECTED"
        elif sig[:2] == b"PK": result["detected_format"] = "ZIP/DOCX"; result["status"] = "PAYLOAD_DETECTED"
        elif sig[:4] == b"%PDF": result["detected_format"] = "PDF"; result["status"] = "PAYLOAD_DETECTED"
        elif sig[:2] == b"MZ": result["detected_format"] = "PE/EXE"; result["status"] = "PAYLOAD_DETECTED"
        elif all(32 <= b <= 126 for b in extracted): result["detected_format"] = "ASCII_TEXT"; result["status"] = "POSSIBLE_PAYLOAD"
    return result


def analyze_f5_capacity(raw_bytes: bytes) -> Dict:
    """Analyze F5 embedding capacity and LSB anomaly score from DCT coefficients.

    F5 (1,7,3) Hamming: raw_capacity ~ n_nonzero_ac / 8 bytes.
    Shrinkage = fraction of +/-1 coefficients that become 0 after embedding.
    LSB imbalance > 5% indicates possible F5 carrier.
    """
    nonzero_ac = get_nonzero_ac_coefficients(raw_bytes)
    n = len(nonzero_ac)
    if n < 16:
        return {
            "status": "INSUFFICIENT_COEFFICIENTS",
            "total_nonzero_ac": n,
            "raw_capacity_bytes": 0,
            "net_capacity_bytes": 0,
            "shrinkage_rate": 0.0,
            "lsb_ratio": 0.5,
            "lsb_anomaly_score": 0.0,
            "f5_indicator": False,
        }
    raw_cap = n // 8
    ones = sum(1 for c in nonzero_ac if abs(c) == 1)
    shrinkage = ones / n
    net_cap = int(raw_cap * (1.0 - shrinkage))
    lsb_0 = sum(1 for c in nonzero_ac if c % 2 == 0)
    lsb_ratio = lsb_0 / n
    lsb_anomaly = abs(lsb_ratio - 0.5) * 100.0
    return {
        "status": "ANALYZED",
        "total_nonzero_ac": n,
        "raw_capacity_bytes": raw_cap,
        "net_capacity_bytes": net_cap,
        "shrinkage_rate": round(shrinkage, 3),
        "lsb_ratio": round(lsb_ratio, 3),
        "lsb_anomaly_score": round(lsb_anomaly, 2),
        "f5_indicator": lsb_anomaly > 5.0,
    }


def analyze_outguess_stats(raw_bytes: bytes) -> Dict:
    """Analyze OutGuess 0.2 histogram signature from DCT coefficients.

    OutGuess corrects histogram after embedding -> over-symmetric AC distribution.
    Natural: symmetry_score ~0.70-0.85. OutGuess-corrected: > 0.90.
    """
    import numpy as np

    blocks = parse_jpeg_dct_coefficients(raw_bytes)
    if not blocks:
        return {"status": "NOT_BASELINE_JPEG", "outguess_score": 0.0, "outguess_indicator": False}
    ac_all: List[int] = [v for block in blocks for v in block[1:]]
    if len(ac_all) < 100:
        return {"status": "INSUFFICIENT_DATA", "outguess_score": 0.0, "outguess_indicator": False}

    hist = np.zeros(101, dtype=np.float64)
    for v in ac_all:
        if -50 <= v <= 50:
            hist[v + 50] += 1
    pos_h = hist[51:]            # +1 to +50
    neg_h = hist[49::-1][:50]   # -1 to -50 (mirrored)
    total = pos_h + neg_h + 1e-9
    diff = np.abs(pos_h - neg_h) / total
    symmetry = float(1.0 - np.mean(diff))
    indicator = symmetry > 0.90
    score = min(100.0, max(0.0, (symmetry - 0.80) * 500.0))
    return {
        "status": "ANALYZED",
        "ac_coefficients_analyzed": len(ac_all),
        "histogram_symmetry_score": round(symmetry, 4),
        "outguess_score": round(score, 2),
        "outguess_indicator": indicator,
    }
