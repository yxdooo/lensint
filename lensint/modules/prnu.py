"""Photo-Response Non-Uniformity (PRNU) Camera Sensor Identification & 1:N Matching Engine.

Implements academic standard digital camera sensor identification based on sensor noise residuals,
2D-FFT circular cross-correlation, Peak-to-Correlation Energy (PCE), and Maximum Likelihood
Estimation (MLE) reference fingerprint generation compliant with forensic courtroom standards.
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from PIL import Image


@dataclass
class PRNUReport:
    """Represents PRNU camera sensor fingerprint analysis and device matching results."""
    fingerprint_extracted: bool = False
    noise_residual_energy: float = 0.0
    matched_device_id: Optional[str] = None
    peak_to_correlation_energy: float = 0.0
    is_device_matched: bool = False
    false_alarm_rate_estimate: float = 1.0
    details: Dict[str, Any] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def extract_noise_residual(pil_img: Image.Image, target_size: Tuple[int, int] = (512, 512)) -> np.ndarray:
    """
    Extract high-frequency PRNU camera sensor noise residual W = I - F(I) from image.
    Uses an adaptive spatial Wiener denoising filter with non-PRNU linear artifact suppression.
    """
    if pil_img is None:
        return np.zeros(target_size, dtype=np.float32)

    # Standardize to grayscale and fixed evaluation window (native center crop / pad)
    w, h = pil_img.size
    if w >= target_size[0] and h >= target_size[1]:
        left = (w - target_size[0]) // 2
        top = (h - target_size[1]) // 2
        crop = pil_img.crop((left, top, left + target_size[0], top + target_size[1])).convert("L")
        arr = np.array(crop, dtype=np.float32)
    else:
        # Avoid destructive sinc interpolation: pad with reflection to preserve physical pixel noise
        raw_arr = np.array(pil_img.convert("L"), dtype=np.float32)
        pad_y = max(0, target_size[1] - raw_arr.shape[0])
        pad_x = max(0, target_size[0] - raw_arr.shape[1])
        arr = np.pad(raw_arr, ((0, pad_y), (0, pad_x)), mode="reflect")[:target_size[1], :target_size[0]]

    # 2D Local Wiener / Mihcak adaptive denoising filter
    padded = np.pad(arr, 2, mode="reflect")
    # 5x5 window local mean and variance
    windows = []
    for dy in range(5):
        for dx in range(5):
            windows.append(padded[dy : dy + target_size[1], dx : dx + target_size[0]])
    stack = np.stack(windows, axis=0)
    local_mean = np.mean(stack, axis=0)
    local_var = np.var(stack, axis=0)

    # High-frequency noise variance estimation using robust median absolute deviation
    laplacian = np.abs(
        arr[1:-1, 1:-1] * 4
        - arr[:-2, 1:-1]
        - arr[2:, 1:-1]
        - arr[1:-1, :-2]
        - arr[1:-1, 2:]
    )
    sigma_noise = float(np.median(laplacian)) / 0.6745 if laplacian.size > 0 else 3.0
    noise_var_estimate = max(1.0, sigma_noise ** 2)

    weight = np.maximum(0.0, local_var - noise_var_estimate) / (local_var + 1e-6)
    denoised = local_mean + weight * (arr - local_mean)

    # Noise residual W = I - F(I)
    noise_residual = arr - denoised

    # Non-PRNU linear artifact suppression (zero-mean rows and columns to suppress JPEG/CMOS readout lines)
    noise_residual -= np.mean(noise_residual, axis=1, keepdims=True)
    noise_residual -= np.mean(noise_residual, axis=0, keepdims=True)

    # Zero-mean and unit variance normalization
    std_res = float(np.std(noise_residual))
    if std_res > 1e-6:
        noise_residual /= std_res

    return noise_residual.astype(np.float32)


def compute_pce(residual: np.ndarray, reference_fingerprint: np.ndarray) -> Tuple[float, float]:
    """
    Compute Peak-to-Correlation Energy (PCE) between an image noise residual and a reference PRNU.
    PCE >= 60.0 indicates courtroom-grade camera device match (False Alarm Rate < 10^-6).
    """
    if residual.shape != reference_fingerprint.shape:
        return 0.0, 1.0

    # 2D-FFT Circular Cross-Correlation
    f_res = np.fft.fft2(residual)
    f_ref = np.fft.fft2(reference_fingerprint)
    cross_power = f_res * np.conj(f_ref)
    norm = np.abs(cross_power)
    norm[norm == 0] = 1.0
    normalized_cross = cross_power / norm

    corr_map = np.real(np.fft.ifft2(normalized_cross))
    # Center correlation map to handle toroidal peak symmetry cleanly
    corr_map_centered = np.fft.fftshift(corr_map)
    corr_map_sq = corr_map_centered ** 2

    # Find peak location
    max_idx = np.unravel_index(np.argmax(corr_map_sq), corr_map_sq.shape)
    peak_val = float(corr_map_sq[max_idx])

    # Exclude 11x11 neighborhood around centered peak to calculate baseline noise energy
    h, w = corr_map_sq.shape
    mask = np.ones((h, w), dtype=bool)
    py, px = max_idx
    y_min, y_max = max(0, py - 5), min(h, py + 6)
    x_min, x_max = max(0, px - 5), min(w, px + 6)
    mask[y_min:y_max, x_min:x_max] = False

    noise_energy = float(np.mean(corr_map_sq[mask])) + 1e-12
    pce = float(peak_val / noise_energy)
    
    # Theoretical False Alarm Rate (FAR) estimation: FAR = 0.5 * erfc(sqrt(PCE) / sqrt(2))
    far = float(0.5 * math.erfc(math.sqrt(max(0.0, pce)) / math.sqrt(2.0)))
    return round(pce, 2), far


class PRNUDatabase:
    """
    1:N Camera Sensor Fingerprint Database for law enforcement and expert witness matching.
    Stores and matches against reference fingerprints extracted from suspect devices.
    """
    def __init__(self):
        self.devices: Dict[str, Dict[str, Any]] = {}

    def register_device_fingerprint(
        self,
        device_id: str,
        fingerprint: np.ndarray,
        device_model: str = "Unknown",
        owner_info: str = "Confidential",
    ) -> None:
        """Register a reference PRNU sensor fingerprint in the database."""
        self.devices[device_id] = {
            "model": device_model,
            "owner": owner_info,
            "fingerprint": fingerprint,
            "shape": list(fingerprint.shape),
        }

    def create_reference_from_images(
        self,
        device_id: str,
        image_list: List[Image.Image],
        device_model: str = "Unknown",
        target_size: Tuple[int, int] = (512, 512),
    ) -> np.ndarray:
        """
        Generate Maximum Likelihood Estimation (MLE) camera sensor fingerprint from calibration photos.
        K_hat = sum(W_i * I_i) / sum(I_i^2)
        """
        if not image_list:
            raise ValueError("At least 1 calibration image is required.")

        accum_wi = np.zeros(target_size, dtype=np.float64)
        accum_i2 = np.zeros(target_size, dtype=np.float64)

        for img in image_list:
            w = extract_noise_residual(img, target_size=target_size)
            w_img, h_img = img.size
            if w_img >= target_size[0] and h_img >= target_size[1]:
                left = (w_img - target_size[0]) // 2
                top = (h_img - target_size[1]) // 2
                crop = img.crop((left, top, left + target_size[0], top + target_size[1])).convert("L")
                arr_i = np.array(crop, dtype=np.float64)
            else:
                raw_i = np.array(img.convert("L"), dtype=np.float64)
                pad_y = max(0, target_size[1] - raw_i.shape[0])
                pad_x = max(0, target_size[0] - raw_i.shape[1])
                arr_i = np.pad(raw_i, ((0, pad_y), (0, pad_x)), mode="reflect")[:target_size[1], :target_size[0]]

            # Normalized intensity [0, 1]
            norm_i = arr_i / 255.0
            accum_wi += (w * norm_i)
            accum_i2 += (norm_i ** 2)

        accum_i2[accum_i2 < 1e-4] = 1.0
        mle_fingerprint = (accum_wi / accum_i2).astype(np.float32)

        # Suppress non-PRNU row/column linear patterns
        mle_fingerprint -= np.mean(mle_fingerprint, axis=1, keepdims=True)
        mle_fingerprint -= np.mean(mle_fingerprint, axis=0, keepdims=True)

        s = float(np.std(mle_fingerprint))
        if s > 1e-6:
            mle_fingerprint /= s

        self.register_device_fingerprint(device_id, mle_fingerprint, device_model=device_model)
        return mle_fingerprint

    def match_image(
        self,
        pil_img: Image.Image,
        pce_threshold: float = 60.0,
        target_size: Tuple[int, int] = (512, 512),
    ) -> PRNUReport:
        """Match unknown image against all registered suspect camera device fingerprints."""
        report = PRNUReport()
        if pil_img is None or not self.devices:
            return report

        residual = extract_noise_residual(pil_img, target_size=target_size)
        report.fingerprint_extracted = True
        report.noise_residual_energy = round(float(np.var(residual)), 4)

        best_pce = 0.0
        best_far = 1.0
        best_device = None

        for dev_id, dev_data in self.devices.items():
            ref = dev_data["fingerprint"]
            pce, far = compute_pce(residual, ref)
            if pce > best_pce:
                best_pce = pce
                best_far = far
                best_device = dev_id

        report.peak_to_correlation_energy = best_pce
        report.false_alarm_rate_estimate = best_far

        if best_pce >= pce_threshold and best_device:
            report.is_device_matched = True
            report.matched_device_id = best_device
            dev_info = self.devices[best_device]
            report.details = {
                "matched_device_id": best_device,
                "model": dev_info.get("model", "Unknown"),
                "pce": best_pce,
                "far": best_far,
            }
            report.findings.append(
                f"Camera PRNU Device Match: Identifies suspect device '{best_device}' "
                f"({dev_info.get('model', 'Unknown')}) with PCE={best_pce:.1f} (PCE Threshold: {pce_threshold}, FAR: {best_far:.2e})."
            )
        elif best_pce > 20.0 and best_device:
            report.findings.append(
                f"Inconclusive PRNU Correlation: Weak peak PCE={best_pce:.1f} detected against '{best_device}' (Below courtroom standard PCE {pce_threshold})."
            )

        return report
