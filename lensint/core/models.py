from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class IntegrityReport:
    file_path: str = ""
    file_name: str = ""
    file_size_bytes: int = 0
    file_size_human: str = ""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    sha512: str = ""
    detected_format: str = "Unknown"
    detected_mime: str = "application/octet-stream"
    extension: str = ""
    extension_mismatch: bool = False
    is_corrupt_or_truncated: bool = False
    dimensions: Optional[Tuple[int, int]] = None
    color_mode: str = ""
    has_alpha_channel: bool = False
    is_screenshot: bool = False
    screen_capture_type: Optional[str] = None
    process_context: List[Dict[str, str]] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MetadataReport:
    exif_present: bool = False
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    lens_model: Optional[str] = None
    software: Optional[str] = None
    artist: Optional[str] = None
    copyright: Optional[str] = None
    device_serial_number: Optional[str] = None
    datetime_original: Optional[str] = None
    datetime_digitized: Optional[str] = None
    datetime_modified: Optional[str] = None
    iso: Optional[int] = None
    exposure_time: Optional[str] = None
    f_number: Optional[str] = None
    focal_length: Optional[str] = None
    flash: Optional[str] = None
    metering_mode: Optional[str] = None
    gps_info: Optional[Dict[str, Any]] = None
    reverse_geocode: Optional[Dict[str, str]] = None
    xmp_present: bool = False
    xmp_data: Dict[str, Any] = field(default_factory=dict)
    iptc_present: bool = False
    iptc_data: Dict[str, Any] = field(default_factory=dict)
    icc_profile: Dict[str, Any] = field(default_factory=dict)
    software_footprint_findings: List[str] = field(default_factory=list)
    timestamp_anomalies: List[str] = field(default_factory=list)
    social_media_provenance: Optional[str] = None
    thumbnail_mismatch_detected: bool = False
    thumbnail_ssim_score: float = 1.0
    thumbnail_extracted: bool = False
    raw_tags: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TamperingReport:
    # 1. Error Level Analysis
    ela_performed: bool = False
    ela_difference_mean: float = 0.0
    ela_difference_max: float = 0.0
    ela_difference_std: float = 0.0
    ela_suspicion_score: float = 0.0
    ela_confidence: float = 0.0
    ela_b64_image: Optional[str] = None

    # 2. Copy-Move (Cloning) Detection
    copy_move_detected: bool = False
    copy_move_match_count: int = 0
    copy_move_confidence: float = 0.0
    copy_move_b64_image: Optional[str] = None

    # 3. JPEG Ghosts (Double Compression)
    jpeg_ghosts_detected: bool = False
    jpeg_ghost_qualities: List[int] = field(default_factory=list)
    jpeg_ghost_difference_score: float = 0.0
    jpeg_ghost_confidence: float = 0.0
    jpeg_ghost_b64_image: Optional[str] = None

    # 4. DQT Quantization Table Forensics
    dqt_found: bool = False
    dqt_identified_encoder: Optional[str] = None
    dqt_quality_estimate: Optional[int] = None
    dqt_hardware_mismatch: bool = False
    dqt_tables: Dict[str, List[int]] = field(default_factory=dict)

    # 5. CFA / Bayer Demosaicing Inconsistency
    cfa_inconsistency_score: float = 0.0
    cfa_tampering_detected: bool = False

    # 6. 8x8 DCT Block Grid Alignment
    block_grid_shifted: bool = False
    block_grid_offset: Tuple[int, int] = (0, 0)
    block_artifact_score: float = 0.0

    # 7. Chromatic Aberration Radial Vector Variance
    chromatic_aberration_inconsistency: float = 0.0
    chromatic_aberration_detected: bool = False

    # 8. Median Filtering / Smoothing Artifacts
    median_filter_detected: bool = False
    median_filter_score: float = 0.0

    # 9. Illumination & Lighting Vector Inconsistency
    illumination_variance_score: float = 0.0
    illumination_conflict_detected: bool = False

    # 10. Laplacian Noise Variance
    noise_inconsistency_score: float = 0.0

    # 11. Splice Detection
    splice_detected: bool = False
    splice_confidence: float = 0.0
    splice_b64_image: Optional[str] = None
    detected_regions: List[Dict[str, Any]] = field(default_factory=list)

    # Contextual Flag
    sensor_heuristics_suppressed: bool = False

    # Overall Verdict
    suspicion_level: str = "LOW"
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StegoReport:
    has_overlay_data: bool = False
    overlay_offset: Optional[int] = None
    overlay_size_bytes: int = 0
    overlay_sha256: Optional[str] = None
    overlay_preview_hex: Optional[str] = None
    embedded_signatures: List[Dict[str, Any]] = field(default_factory=list)
    lsb_entropy: Dict[str, float] = field(default_factory=dict)
    lsb_stego_detected: bool = False
    lsb_stego_confidence: float = 0.0
    rs_steganalysis_detected: bool = False
    rs_estimated_embedding_rate: float = 0.0
    stego_tool_signatures: List[str] = field(default_factory=list)
    c2_stego_detected: bool = False
    dct_stego_detected: bool = False
    f5_anomaly_detected: bool = False
    outguess_anomaly_detected: bool = False
    jsteg_payload_detected: bool = False
    extracted_passphrase_payload: Optional[str] = None
    extracted_payload_type: Optional[str] = None
    bitplane_b64_images: Dict[str, str] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StringsReport:
    total_strings_found: int = 0
    extracted_ascii_count: int = 0
    extracted_utf16_count: int = 0
    iocs_detected: Dict[str, List[str]] = field(default_factory=lambda: {
        "ipv4": [],
        "ipv6": [],
        "urls": [],
        "domains": [],
        "emails": [],
        "base64_blobs": [],
        "shell_commands": [],
        "crypto_wallets": []
    })
    suspicious_strings: List[str] = field(default_factory=list)
    sample_strings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AIDetectionReport:
    is_ai_generated: bool = False
    ai_probability_score: float = 0.0
    ai_verdict: str = "ORGANIC_NATURAL"
    ai_generator_detected: bool = False
    ai_generator_name: Optional[str] = None
    c2pa_present: bool = False
    c2pa_markers: List[str] = field(default_factory=list)
    prompt_parameters: Dict[str, Any] = field(default_factory=dict)
    prompt_injection_detected: bool = False
    fft_analyzed: bool = False
    fft_spectral_score: float = 0.0
    fft_peak_ratio: float = 0.0
    fft_b64_image: Optional[str] = None
    gan_fingerprint_detected: bool = False
    gan_fingerprint_score: float = 0.0
    diffusion_artifact_score: float = 0.0
    prnu_sensor_noise_detected: bool = False
    prnu_sensor_score: float = 0.0
    inpainting_anomaly_score: float = 0.0
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MalwareReport:
    has_threats: bool = False
    severity: str = "CLEAN"
    is_polyglot: bool = False
    polyglot_types: List[str] = field(default_factory=list)
    webshell_detected: bool = False
    shellcode_detected: bool = False
    threat_signatures: List[str] = field(default_factory=list)
    high_entropy_sections: List[Dict[str, Any]] = field(default_factory=list)
    packed_payload_detected: bool = False
    yara_matches: List[Dict[str, Any]] = field(default_factory=list)
    deobfuscated_payloads: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatIntelReport:
    virustotal_file_url: Optional[str] = None
    hybrid_analysis_url: Optional[str] = None
    ip_lookups: Dict[str, Dict[str, str]] = field(default_factory=dict)
    domain_lookups: Dict[str, Dict[str, str]] = field(default_factory=dict)
    reverse_image_engines: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OCRReport:
    ocr_performed: bool = False
    engine_used: str = "None"
    text_detected: bool = False
    extracted_text: str = ""
    character_count: int = 0
    word_count: int = 0
    sensitive_findings: List[Dict[str, Any]] = field(default_factory=list)
    api_keys_found: List[str] = field(default_factory=list)
    passwords_found: List[str] = field(default_factory=list)
    tokens_found: List[str] = field(default_factory=list)
    pii_found: List[str] = field(default_factory=list)
    private_keys_found: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    target_path: str = ""
    timestamp: str = ""
    overall_risk_score: float = 0.0
    overall_risk_level: str = "CLEAN"
    summary_findings: List[str] = field(default_factory=list)
    analysis_duration_seconds: float = 0.0
    cache_hit: bool = False
    integrity: IntegrityReport = field(default_factory=IntegrityReport)
    metadata: MetadataReport = field(default_factory=MetadataReport)
    tampering: TamperingReport = field(default_factory=TamperingReport)
    stego: StegoReport = field(default_factory=StegoReport)
    strings: StringsReport = field(default_factory=StringsReport)
    ai_detection: AIDetectionReport = field(default_factory=AIDetectionReport)
    malware: MalwareReport = field(default_factory=MalwareReport)
    threat_intel: ThreatIntelReport = field(default_factory=ThreatIntelReport)
    ocr: OCRReport = field(default_factory=OCRReport)
    fusion_telemetry: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "timestamp": self.timestamp,
            "overall_risk_score": self.overall_risk_score,
            "overall_risk_level": self.overall_risk_level,
            "summary_findings": self.summary_findings,
            "analysis_duration_seconds": self.analysis_duration_seconds,
            "cache_hit": self.cache_hit,
            "integrity": self.integrity.to_dict(),
            "metadata": self.metadata.to_dict(),
            "tampering": self.tampering.to_dict(),
            "stego": self.stego.to_dict(),
            "strings": self.strings.to_dict(),
            "ai_detection": self.ai_detection.to_dict(),
            "malware": self.malware.to_dict(),
            "threat_intel": self.threat_intel.to_dict(),
            "ocr": self.ocr.to_dict(),
            "fusion_telemetry": self.fusion_telemetry,
        }
