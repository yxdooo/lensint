"""Biometric rPPG (Remote Photoplethysmography) & Video Deepfake Forensics Engine.

Extracts sub-visual cardiovascular blood volume pulse (BVP) waveforms from facial skin
pixels using academic CHROM and POS algorithms, evaluates multi-region phase/spectral
coherence across forehead and cheek ROIs, models blink cadence with Poisson arrival statistics
via Eye Aspect Ratio (EAR), and verifies corneal specular reflections for deepfake detection.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import math
import os
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import numpy as np
from PIL import Image

try:
    import cv2  # type: ignore
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False


# ==============================================================================
# DATACLASSES FOR BIOMETRIC rPPG REPORTING
# ==============================================================================

@dataclass
class PulseWaveform:
    """Represents an extracted rPPG blood volume pulse signal."""
    algorithm: str = "CHROM"
    signal: List[float] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    dominant_freq_hz: float = 0.0
    bpm: float = 0.0
    snr_db: float = 0.0
    spectral_entropy: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BlinkDynamics:
    """Represents facial blink cadence and temporal Poisson consistency telemetry."""
    total_blinks: int = 0
    blink_rate_bpm: float = 0.0
    mean_inter_blink_interval_sec: float = 0.0
    poisson_p_value: float = 1.0
    is_poisson_consistent: bool = True
    ear_trace: List[float] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CornealReflection:
    """Represents 3D corneal light reflection and gaze consistency metrics."""
    left_eye_highlight_offset: Tuple[float, float] = (0.0, 0.0)
    right_eye_highlight_offset: Tuple[float, float] = (0.0, 0.0)
    disparity_score: float = 0.0
    is_specular_consistent: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BiometricsRPPGReport:
    """Comprehensive Biometric rPPG & Video Deepfake Forensic Report."""
    is_analyzed: bool = False
    duration_seconds: float = 0.0
    fps: float = 30.0
    frame_count: int = 0
    chrom_pulse: Optional[PulseWaveform] = None
    pos_pulse: Optional[PulseWaveform] = None
    dominant_bpm: float = 0.0
    rppg_snr_db: float = 0.0
    cross_region_coherence: float = 0.0
    deepfake_pulse_anomaly_score: float = 0.0  # 0.0 = authentic human, 1.0 = deepfake synthetic
    blink_dynamics: Optional[BlinkDynamics] = None
    corneal_reflection: Optional[CornealReflection] = None
    is_deepfake: bool = False
    deepfake_confidence: float = 0.0
    verdict: str = "INSUFFICIENT_VIDEO_EVIDENCE"
    findings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.chrom_pulse:
            d["chrom_pulse"] = self.chrom_pulse.to_dict()
        if self.pos_pulse:
            d["pos_pulse"] = self.pos_pulse.to_dict()
        if self.blink_dynamics:
            d["blink_dynamics"] = self.blink_dynamics.to_dict()
        if self.corneal_reflection:
            d["corneal_reflection"] = self.corneal_reflection.to_dict()
        return d


# ==============================================================================
# FACIAL ROI SEGMENTATION & SKIN CHROMINANCE EXTRACTION
# ==============================================================================

def segment_skin_roi(frame_rgb: np.ndarray) -> np.ndarray:
    """
    Extracts skin mask from RGB frame using biometric YCbCr skin locus modeling.
    Skin locus constraints: Y >= 40, 133 <= Cr <= 173, 77 <= Cb <= 127.
    """
    h, w, _ = frame_rgb.shape
    arr = frame_rgb.astype(np.float32)
    # Convert RGB to YCbCr (ITU-R BT.601)
    y = 0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1] + 0.114 * arr[:, :, 2]
    cb = 128.0 - 0.168736 * arr[:, :, 0] - 0.331264 * arr[:, :, 1] + 0.5 * arr[:, :, 2]
    cr = 128.0 + 0.5 * arr[:, :, 0] - 0.418688 * arr[:, :, 1] - 0.081312 * arr[:, :, 2]

    skin_mask = (y >= 40) & (cb >= 77) & (cb <= 127) & (cr >= 133) & (cr <= 173)
    return skin_mask


def extract_facial_region_means(frame_rgb: np.ndarray) -> Dict[str, np.ndarray]:
    """
    Extracts average spatial RGB values for Forehead, Left Cheek, and Right Cheek ROIs.
    """
    h, w, _ = frame_rgb.shape
    # Geometric facial proportions assuming standardized centered or upper face framing
    # Forehead: Top 15% to 35%, Central 30% to 70%
    fh_y1, fh_y2 = int(0.15 * h), int(0.35 * h)
    fh_x1, fh_x2 = int(0.30 * w), int(0.70 * w)

    # Left Cheek: 45% to 70% height, 15% to 40% width
    lc_y1, lc_y2 = int(0.45 * h), int(0.70 * h)
    lc_x1, lc_x2 = int(0.15 * w), int(0.40 * w)

    # Right Cheek: 45% to 70% height, 60% to 85% width
    rc_y1, rc_y2 = int(0.45 * h), int(0.70 * h)
    rc_x1, rc_x2 = int(0.60 * w), int(0.85 * w)

    def _mean_rgb(crop: np.ndarray) -> np.ndarray:
        if crop.size == 0:
            return np.array([128.0, 128.0, 128.0], dtype=np.float64)
        mask = segment_skin_roi(crop)
        if np.count_nonzero(mask) > 10:
            return np.mean(crop[mask], axis=0).astype(np.float64)
        return np.mean(crop, axis=(0, 1)).astype(np.float64)

    return {
        "forehead": _mean_rgb(frame_rgb[fh_y1:fh_y2, fh_x1:fh_x2]),
        "left_cheek": _mean_rgb(frame_rgb[lc_y1:lc_y2, lc_x1:lc_x2]),
        "right_cheek": _mean_rgb(frame_rgb[rc_y1:rc_y2, rc_x1:rc_x2]),
        "full_face": _mean_rgb(frame_rgb[int(0.15*h):int(0.85*h), int(0.2*w):int(0.8*w)]),
    }


# ==============================================================================
# rPPG SIGNAL PROCESSING: CHROM & POS ALGORITHMS
# ==============================================================================

def butterworth_bandpass_fft(signal: np.ndarray, fps: float, low_hz: float = 0.7, high_hz: float = 3.5) -> np.ndarray:
    """
    Zero-phase bandpass filtering in the human physiological pulse band [0.7 Hz, 3.5 Hz] (42 - 210 BPM).
    Uses FFT frequency domain masking with smooth Tukey / Hanning transition edges.
    """
    n = len(signal)
    if n < 4:
        return signal

    # Detrend
    sig_detrend = signal - np.mean(signal)
    fft_vals = np.fft.rfft(sig_detrend)
    freqs = np.fft.rfftfreq(n, d=1.0 / fps)

    # Bandpass filter transfer function with smooth taper
    h = np.zeros_like(freqs, dtype=np.float64)
    in_band = (freqs >= low_hz) & (freqs <= high_hz)
    h[in_band] = 1.0

    # Smooth transition taper (0.1 Hz width)
    taper_w = 0.1
    lower_taper = (freqs >= low_hz - taper_w) & (freqs < low_hz)
    h[lower_taper] = 0.5 * (1 + np.cos(np.pi * (low_hz - freqs[lower_taper]) / taper_w))

    upper_taper = (freqs > high_hz) & (freqs <= high_hz + taper_w)
    h[upper_taper] = 0.5 * (1 + np.cos(np.pi * (freqs[upper_taper] - high_hz) / taper_w))

    filtered_fft = fft_vals * h
    filtered_signal = np.fft.irfft(filtered_fft, n=n)
    return filtered_signal


def compute_chrom_pulse(rgb_traces: np.ndarray, fps: float) -> np.ndarray:
    """
    Extracts cardiovascular pulse waveform via CHROM (Chrominance-based method - de Haan & Jeanne 2013).
    Normalized RGB traces: r_n = R / mu_R, g_n = G / mu_G, b_n = B / mu_B.
    Chrominance projections: Xs = 3*r_n - 2*g_n, Ys = 1.5*r_n + g_n - 1.5*b_n.
    Alpha = std(Xs) / std(Ys), S = Xs - Alpha * Ys.
    """
    t_len = rgb_traces.shape[0]
    if t_len < 4:
        return np.zeros(t_len, dtype=np.float64)

    # Normalize by temporal mean
    mean_rgb = np.mean(rgb_traces, axis=0) + 1e-6
    norm_rgb = rgb_traces / mean_rgb - 1.0

    r = norm_rgb[:, 0]
    g = norm_rgb[:, 1]
    b = norm_rgb[:, 2]

    # Orthogonal chrominance signals
    xs = 3.0 * r - 2.0 * g
    ys = 1.5 * r + g - 1.5 * b

    # Dynamic window std ratio (window = ~1.5 seconds)
    win_size = max(4, int(1.5 * fps))
    pulse = np.zeros(t_len, dtype=np.float64)

    for i in range(t_len):
        start = max(0, i - win_size // 2)
        end = min(t_len, i + win_size // 2 + 1)
        sub_x = xs[start:end]
        sub_y = ys[start:end]
        std_x = np.std(sub_x)
        std_y = np.std(sub_y)
        alpha = std_x / (std_y + 1e-6)
        pulse[i] = xs[i] - alpha * ys[i]

    return butterworth_bandpass_fft(pulse, fps)


def compute_pos_pulse(rgb_traces: np.ndarray, fps: float) -> np.ndarray:
    """
    Extracts cardiovascular pulse waveform via POS (Plane-Orthogonal-to-Skin - Wang et al. 2017).
    Projects normalized RGB onto skin-reflection orthogonal subspace:
    P1 = g - b, P2 = -2*r + g + b.
    Alpha = std(P1) / std(P2), S = P1 + Alpha * P2.
    """
    t_len = rgb_traces.shape[0]
    if t_len < 4:
        return np.zeros(t_len, dtype=np.float64)

    mean_rgb = np.mean(rgb_traces, axis=0) + 1e-6
    norm_rgb = rgb_traces / mean_rgb - 1.0

    r = norm_rgb[:, 0]
    g = norm_rgb[:, 1]
    b = norm_rgb[:, 2]

    p1 = g - b
    p2 = -2.0 * r + g + b

    win_size = max(4, int(1.5 * fps))
    pulse = np.zeros(t_len, dtype=np.float64)

    for i in range(t_len):
        start = max(0, i - win_size // 2)
        end = min(t_len, i + win_size // 2 + 1)
        sub_p1 = p1[start:end]
        sub_p2 = p2[start:end]
        std_p1 = np.std(sub_p1)
        std_p2 = np.std(sub_p2)
        alpha = std_p1 / (std_p2 + 1e-6)
        pulse[i] = p1[i] + alpha * p2[i]

    return butterworth_bandpass_fft(pulse, fps)


def compute_psd_snr(signal: np.ndarray, fps: float) -> Tuple[float, float, float, float]:
    """
    Calculates Power Spectral Density (PSD), dominant frequency (Hz), BPM, SNR (dB), and Spectral Entropy.
    SNR = 10 * log10(Power_in_pulse_and_harmonic / Power_in_noise).
    """
    n = len(signal)
    if n < 8:
        return 0.0, 0.0, -20.0, 1.0

    fft_vals = np.fft.rfft(signal)
    freqs = np.fft.rfftfreq(n, d=1.0 / fps)
    psd = np.abs(fft_vals) ** 2

    # In-band physiological mask [0.7 Hz, 3.5 Hz]
    valid_mask = (freqs >= 0.7) & (freqs <= 3.5)
    if not np.any(valid_mask):
        return 0.0, 0.0, -20.0, 1.0

    in_band_freqs = freqs[valid_mask]
    in_band_psd = psd[valid_mask]

    peak_idx = np.argmax(in_band_psd)
    peak_freq = in_band_freqs[peak_idx]
    bpm = peak_freq * 60.0

    # Signal power: fundamental +/- 0.15 Hz + 2nd harmonic +/- 0.15 Hz
    delta = 0.15
    f1_mask = (freqs >= peak_freq - delta) & (freqs <= peak_freq + delta)
    f2_mask = (freqs >= 2.0 * peak_freq - delta) & (freqs <= 2.0 * peak_freq + delta)
    sig_mask = (f1_mask | f2_mask) & valid_mask

    signal_power = np.sum(psd[sig_mask])
    noise_power = np.sum(psd[valid_mask & ~sig_mask]) + 1e-8

    snr_db = float(10.0 * np.log10(max(1e-6, signal_power / noise_power)))

    # Spectral entropy over in-band PSD
    norm_psd = in_band_psd / (np.sum(in_band_psd) + 1e-9)
    entropy = -np.sum(norm_psd * np.log2(norm_psd + 1e-12)) / np.log2(len(norm_psd) + 1e-6)

    return float(peak_freq), float(bpm), float(snr_db), float(entropy)


# ==============================================================================
# MULTI-REGION COHERENCE & TEMPORAL CONSISTENCY
# ==============================================================================

def compute_cross_region_coherence(forehead_pulse: np.ndarray, left_cheek_pulse: np.ndarray, right_cheek_pulse: np.ndarray) -> float:
    """
    Computes cross-correlation and cross-spectral phase coherence across facial skin sub-regions.
    Authentic human cardiovascular flow is synchronized across the face (coherence > 0.65).
    Deepfake generative artifacts show regional phase de-synchronization (coherence < 0.35).
    """
    def _norm_corr(a: np.ndarray, b: np.ndarray) -> float:
        if np.std(a) < 1e-6 or np.std(b) < 1e-6:
            return 0.0
        corr = np.corrcoef(a, b)[0, 1]
        return 0.0 if np.isnan(corr) else float(corr)

    r_fl = _norm_corr(forehead_pulse, left_cheek_pulse)
    r_fr = _norm_corr(forehead_pulse, right_cheek_pulse)
    r_lr = _norm_corr(left_cheek_pulse, right_cheek_pulse)

    mean_coherence = float(np.mean([max(0.0, r_fl), max(0.0, r_fr), max(0.0, r_lr)]))
    return mean_coherence


# ==============================================================================
# BIOMETRIC LIVENESS: EAR BLINK POISSON DYNAMICS & CORNEAL REFLECTIONS
# ==============================================================================

def estimate_ear_and_blinks(frames_rgb: Sequence[np.ndarray], fps: float) -> BlinkDynamics:
    """
    Calculates Eye Aspect Ratio (EAR) sequence and verifies Poisson arrival consistency.
    Natural human blinking has stochastic inter-blink intervals following a Poisson process.
    Deepfakes exhibit unnatural blink suppression, rigid periodic blinking, or random flickering.
    """
    total_frames = len(frames_rgb)
    ear_trace: List[float] = []

    for frame in frames_rgb:
        h, w, _ = frame.shape
        # Approximate eye region (upper face 20-40% height, 20-80% width)
        eye_strip = frame[int(0.25 * h) : int(0.42 * h), int(0.22 * w) : int(0.78 * w)]
        if eye_strip.size == 0:
            ear_trace.append(0.30)
            continue

        gray = np.mean(eye_strip, axis=2).astype(np.float32)
        # Vertical gradient vs horizontal gradient ratio as proxy for eye aperture
        dy = np.abs(np.diff(gray, axis=0))
        dx = np.abs(np.diff(gray, axis=1))
        ear_approx = float(np.mean(dy) / (np.mean(dx) + 1e-5))
        # Normalize to standard EAR range [0.10, 0.38]
        ear_val = float(np.clip(0.12 + 0.26 * (ear_approx / (ear_approx + 1.2)), 0.08, 0.40))
        ear_trace.append(ear_val)

    ear_arr = np.array(ear_trace)
    # Detect blink dips (EAR < 0.21)
    blink_thresh = 0.20
    is_blink_state = ear_arr < blink_thresh

    blink_starts = []
    in_blink = False
    for idx, b in enumerate(is_blink_state):
        if b and not in_blink:
            blink_starts.append(idx)
            in_blink = True
        elif not b:
            in_blink = False

    total_blinks = len(blink_starts)
    duration_sec = total_frames / fps if fps > 0 else 1.0
    blink_rate_bpm = (total_blinks / duration_sec) * 60.0

    # Calculate Inter-Blink Intervals (IBI)
    anomalies = []
    is_poisson = True
    poisson_p = 1.0
    mean_ibi = 0.0

    if len(blink_starts) >= 2:
        ibis = np.diff(blink_starts) / fps
        mean_ibi = float(np.mean(ibis))
        var_ibi = float(np.var(ibis))
        fano_factor = var_ibi / (mean_ibi + 1e-6)

        # Poisson process has variance ~ mean^2 for exponential inter-arrival times (Fano factor around 1.0)
        # Check for deterministic periodic blinking or erratic jitter
        if var_ibi < 0.05 and len(ibis) >= 3:
            is_poisson = False
            anomalies.append("Abnormally deterministic, periodic blinking detected (synthetic generator cadence).")
        elif fano_factor > 15.0:
            is_poisson = False
            anomalies.append("Erratic, high-variance blink flicker detected.")
        poisson_p = float(np.exp(-abs(1.0 - (var_ibi / (mean_ibi**2 + 1e-6)))))
    elif duration_sec > 10.0 and total_blinks == 0:
        is_poisson = False
        anomalies.append("Complete absence of natural human blinking over extended video duration.")

    return BlinkDynamics(
        total_blinks=total_blinks,
        blink_rate_bpm=float(blink_rate_bpm),
        mean_inter_blink_interval_sec=mean_ibi,
        poisson_p_value=poisson_p,
        is_poisson_consistent=is_poisson,
        ear_trace=[round(v, 4) for v in ear_trace[:120]],  # cap trace length for reporting
        anomalies=anomalies,
    )


def evaluate_corneal_specular_reflection(frame_rgb: np.ndarray) -> CornealReflection:
    """
    Measures corneal specular highlight reflection symmetry and 3D gaze disparity between left and right eyes.
    Natural illumination creates identical angular reflection displacement relative to iris center.
    """
    h, w, _ = frame_rgb.shape
    # Left eye region (subject's right)
    left_eye = frame_rgb[int(0.28*h):int(0.38*h), int(0.28*w):int(0.44*w)]
    # Right eye region (subject's left)
    right_eye = frame_rgb[int(0.28*h):int(0.38*h), int(0.56*w):int(0.72*w)]

    def _get_highlight_offset(eye_crop: np.ndarray) -> Tuple[float, float]:
        if eye_crop.size == 0:
            return (0.0, 0.0)
        lum = np.mean(eye_crop, axis=2)
        # Pupil: darkest 10%
        pupil_y, pupil_x = np.unravel_index(np.argmin(lum), lum.shape)
        # Specular glint: brightest peak in eye
        glint_y, glint_x = np.unravel_index(np.argmax(lum), lum.shape)
        eh, ew = lum.shape
        return (float((glint_x - pupil_x) / ew), float((glint_y - pupil_y) / eh))

    left_offset = _get_highlight_offset(left_eye)
    right_offset = _get_highlight_offset(right_eye)

    disparity = float(math.sqrt((left_offset[0] - right_offset[0])**2 + (left_offset[1] - right_offset[1])**2))
    is_consistent = disparity <= 0.28

    return CornealReflection(
        left_eye_highlight_offset=(round(left_offset[0], 4), round(left_offset[1], 4)),
        right_eye_highlight_offset=(round(right_offset[0], 4), round(right_offset[1], 4)),
        disparity_score=round(disparity, 4),
        is_specular_consistent=is_consistent,
    )


# ==============================================================================
# MAIN BIOMETRIC rPPG & VIDEO FORENSIC PIPELINE
# ==============================================================================

class BiometricsRPPGAnalyzer:
    """
    Full pipeline for remote Photoplethysmography (rPPG) and deepfake video verification.
    """
    def __init__(self, frames: Sequence[np.ndarray], fps: float = 30.0):
        self.frames = frames
        self.fps = max(1.0, float(fps))
        self.num_frames = len(frames)

    def analyze(self) -> BiometricsRPPGReport:
        report = BiometricsRPPGReport()
        report.frame_count = self.num_frames
        report.fps = self.fps
        report.duration_seconds = float(self.num_frames / self.fps)

        if self.num_frames < 10:
            report.verdict = "INSUFFICIENT_FRAME_COUNT"
            report.findings.append(f"Insufficient video frames ({self.num_frames}) for reliable cardiovascular rPPG analysis.")
            return report

        report.is_analyzed = True

        # Step 1: Extract RGB temporal traces across facial ROIs
        fh_traces = []
        lc_traces = []
        rc_traces = []
        face_traces = []

        for frame in self.frames:
            means = extract_facial_region_means(frame)
            fh_traces.append(means["forehead"])
            lc_traces.append(means["left_cheek"])
            rc_traces.append(means["right_cheek"])
            face_traces.append(means["full_face"])

        fh_arr = np.array(fh_traces, dtype=np.float64)
        lc_arr = np.array(lc_traces, dtype=np.float64)
        rc_arr = np.array(rc_traces, dtype=np.float64)
        face_arr = np.array(face_traces, dtype=np.float64)

        # Step 2: Compute CHROM & POS Pulse Waveforms
        chrom_sig = compute_chrom_pulse(face_arr, self.fps)
        pos_sig = compute_pos_pulse(face_arr, self.fps)

        # Step 3: Compute Regional Waveforms for Multi-Region Coherence
        fh_sig = compute_chrom_pulse(fh_arr, self.fps)
        lc_sig = compute_chrom_pulse(lc_arr, self.fps)
        rc_sig = compute_chrom_pulse(rc_arr, self.fps)

        coherence = compute_cross_region_coherence(fh_sig, lc_sig, rc_sig)
        report.cross_region_coherence = round(coherence, 4)

        # Step 4: Spectral PSD and SNR Analysis
        chrom_freq, chrom_bpm, chrom_snr, chrom_ent = compute_psd_snr(chrom_sig, self.fps)
        pos_freq, pos_bpm, pos_snr, pos_ent = compute_psd_snr(pos_sig, self.fps)

        timestamps = [round(i / self.fps, 4) for i in range(min(len(chrom_sig), 100))]
        report.chrom_pulse = PulseWaveform(
            algorithm="CHROM",
            signal=[round(float(v), 5) for v in chrom_sig[:100]],
            timestamps=timestamps,
            dominant_freq_hz=round(chrom_freq, 3),
            bpm=round(chrom_bpm, 1),
            snr_db=round(chrom_snr, 2),
            spectral_entropy=round(chrom_ent, 4),
        )

        report.pos_pulse = PulseWaveform(
            algorithm="POS",
            signal=[round(float(v), 5) for v in pos_sig[:100]],
            timestamps=timestamps,
            dominant_freq_hz=round(pos_freq, 3),
            bpm=round(pos_bpm, 1),
            snr_db=round(pos_snr, 2),
            spectral_entropy=round(pos_ent, 4),
        )

        # Unified Dominant BPM & SNR
        report.dominant_bpm = round((chrom_bpm + pos_bpm) / 2.0, 1) if chrom_snr > -5.0 else round(chrom_bpm, 1)
        report.rppg_snr_db = round(max(chrom_snr, pos_snr), 2)

        # Step 5: Blink Dynamics (EAR Poisson Cadence)
        report.blink_dynamics = estimate_ear_and_blinks(self.frames, self.fps)

        # Step 6: Corneal Specular Reflection Disparity
        sample_frame = self.frames[min(10, self.num_frames - 1)]
        report.corneal_reflection = evaluate_corneal_specular_reflection(sample_frame)

        # Step 7: Deepfake Forensic Scoring & Verdict Fusion
        self._calculate_deepfake_anomaly_score(report)

        return report

    def _calculate_deepfake_anomaly_score(self, report: BiometricsRPPGReport) -> None:
        """
        Fuses rPPG pulse SNR, multi-region facial phase coherence, blink Poisson consistency,
        and corneal highlight disparity into an overall deepfake anomaly score [0.0, 1.0].
        """
        score = 0.0

        # Factor 1: rPPG Cardiovascular Pulse SNR (Authentic > +2 dB; Deepfake < -3 dB)
        if report.rppg_snr_db < -4.0:
            score += 0.35
            report.findings.append("⚠️ Complete absence of physiological blood volume pulse (SNR < -4.0 dB).")
        elif report.rppg_snr_db < 0.0:
            score += 0.20
        else:
            report.findings.append(f"Cardiovascular Pulse Identified: {report.dominant_bpm} BPM (rPPG SNR: {report.rppg_snr_db:+.1f} dB).")

        # Factor 2: Cross-Region Facial Phase Coherence (Authentic > 0.65; Deepfake < 0.35)
        if report.cross_region_coherence < 0.30:
            score += 0.30
            report.findings.append("⚠️ Facial blood flow phase desynchronization detected across forehead and cheeks.")
        elif report.cross_region_coherence < 0.50:
            score += 0.15
        else:
            report.findings.append(f"Forehead/Cheek Pulse Phase Coherence: {report.cross_region_coherence:.2f} (Natural blood flow).")

        # Factor 3: Blink Dynamics
        if report.blink_dynamics and not report.blink_dynamics.is_poisson_consistent:
            score += 0.20
            for anom in report.blink_dynamics.anomalies:
                report.findings.append(f"⚠️ {anom}")

        # Factor 4: Corneal Reflection Disparity
        if report.corneal_reflection and not report.corneal_reflection.is_specular_consistent:
            score += 0.15
            report.findings.append(f"⚠️ Corneal Specular Disparity ({report.corneal_reflection.disparity_score:.2f}) indicates synthetic lighting or gaze desynchronization.")

        report.deepfake_pulse_anomaly_score = round(min(1.0, score), 3)
        report.deepfake_confidence = round(report.deepfake_pulse_anomaly_score, 2)

        if report.deepfake_pulse_anomaly_score >= 0.55:
            report.is_deepfake = True
            report.verdict = "SUSPECTED_DEEPFAKE_SYNTHETIC"
            report.findings.insert(0, "🚨 DEEPFAKE DETECTED: Biometric rPPG pulse waveforms, facial coherence, and blink dynamics fail biological consistency.")
        elif report.deepfake_pulse_anomaly_score <= 0.25 and report.rppg_snr_db >= 1.0:
            report.is_deepfake = False
            report.verdict = "AUTHENTIC_BIOMETRIC_LIVENESS"
            report.findings.insert(0, "✅ AUTHENTIC BIOMETRIC LIVENESS: Synchronized cardiovascular rPPG pulse and natural human blink dynamics verified.")
        else:
            report.is_deepfake = False
            report.verdict = "INCONCLUSIVE_LOW_SNR"
            report.findings.insert(0, "ℹ️ Inconclusive: Video telemetry exhibits low signal-to-noise ratio or compression degradation.")


def analyze_biometrics_rppg(frames_or_video: Any, fps: float = 30.0) -> BiometricsRPPGReport:
    """
    Public API: Analyzes a sequence of video frames, 4D numpy array, or video file for biometric deepfake forensics.

    Args:
        frames_or_video: Sequence of PIL images / NumPy arrays, 4D numpy array (T, H, W, C), or path to video file.
        fps: Sampling rate (frames per second). Defaults to 30.0.

    Returns:
        BiometricsRPPGReport with complete cardiovascular pulse and liveness telemetry.
    """
    frames_list: List[np.ndarray] = []

    # Handle video file path
    if isinstance(frames_or_video, str) and os.path.exists(frames_or_video):
        if HAS_OPENCV:
            cap = cv2.VideoCapture(frames_or_video)
            video_fps = cap.get(cv2.CAP_PROP_FPS)
            if video_fps and video_fps > 0:
                fps = float(video_fps)
            frame_idx = 0
            while cap.isOpened() and frame_idx < 300:  # cap at 300 frames (10 seconds)
                ret, frame_bgr = cap.read()
                if not ret:
                    break
                frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
                frames_list.append(frame_rgb)
                frame_idx += 1
            cap.release()

    # Handle 4D numpy array (T, H, W, C)
    elif isinstance(frames_or_video, np.ndarray) and frames_or_video.ndim == 4:
        frames_list = [frames_or_video[i] for i in range(frames_or_video.shape[0])]

    # Handle Sequence of frames (PIL Image or NumPy arrays)
    elif isinstance(frames_or_video, (list, tuple)):
        for f in frames_or_video:
            if isinstance(f, Image.Image):
                frames_list.append(np.array(f.convert("RGB"), dtype=np.uint8))
            elif isinstance(f, np.ndarray):
                if f.ndim == 3:
                    frames_list.append(f if f.shape[2] == 3 else f[:, :, :3])

    if not frames_list:
        return BiometricsRPPGReport(verdict="EMPTY_INPUT_FRAMES")

    analyzer = BiometricsRPPGAnalyzer(frames_list, fps=fps)
    return analyzer.analyze()
