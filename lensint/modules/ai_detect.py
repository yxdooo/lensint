import json
import re
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from PIL import Image

from lensint.core.models import AIDetectionReport
from lensint.utils.image_ops import numpy_to_base64_png

AI_METADATA_PATTERNS = [
    ("prompt", "Prompt"),
    ("negative_prompt", "Negative Prompt"),
    ("steps", "Generation Steps"),
    ("sampler", "Sampler"),
    ("cfg scale", "CFG Scale"),
    ("seed", "Seed"),
    ("model hash", "Model Hash"),
    ("model", "Model Name"),
]

C2PA_SIGNATURES = [
    b"c2pa",
    b"C2PA",
    b"urn:c2pa",
    b"jumb",
    b"Adobe Content Authenticity",
    b"OpenAI",
    b"Midjourney",
    b"DALL-E",
    b"StableDiffusion",
    b"NovelAI",
]


def calculate_fft_spectrum(pil_img: Image.Image) -> Tuple[np.ndarray, float, float, bool]:
    gray = np.array(pil_img.convert("L"), dtype=np.float32)
    h, w = gray.shape

    min_dim = min(h, w)
    crop_size = 512 if min_dim >= 512 else (256 if min_dim >= 256 else min_dim)
    sy, sx = (h - crop_size) // 2, (w - crop_size) // 2
    cropped = gray[sy : sy + crop_size, sx : sx + crop_size]

    fft2 = np.fft.fft2(cropped)
    fft_shifted = np.fft.fftshift(fft2)
    magnitude = np.log(np.abs(fft_shifted) + 1.0)
    mn, mx = np.min(magnitude), np.max(magnitude)
    norm_vis = ((magnitude - mn) / (mx - mn + 1e-6) * 255.0).astype(np.uint8)

    cy, cx = crop_size // 2, crop_size // 2
    y, x = np.ogrid[:crop_size, :crop_size]
    dist = np.sqrt((x - cx) ** 2 + (y - cy) ** 2)
    mask = (dist > crop_size * 0.25) & (dist < crop_size * 0.48)
    hf = magnitude[mask]

    if len(hf) == 0:
        return norm_vis, 0.0, 0.0, False

    mean_hf, std_hf, max_hf = float(np.mean(hf)), float(np.std(hf)), float(np.max(hf))
    peak_ratio = (max_hf - mean_hf) / (std_hf + 1e-6)
    score = min(100.0, max(0.0, (peak_ratio - 3.0) * 18.0))
    return norm_vis, round(score, 2), round(peak_ratio, 2), score >= 50.0


def analyze_gan_fingerprint(arr: Any) -> Tuple[bool, float, float]:
    if isinstance(arr, Image.Image):
        arr = np.array(arr.convert("L"), dtype=np.float32)
    elif isinstance(arr, np.ndarray) and len(arr.shape) == 3:
        arr = np.mean(arr.astype(np.float32), axis=2)

    if np.iscomplexobj(arr):
        fft_shifted = arr
    else:
        fft2 = np.fft.fft2(arr)
        fft_shifted = np.fft.fftshift(fft2)

    magnitude = np.log(np.abs(fft_shifted) + 1.0)
    h, w = magnitude.shape[:2]
    cy, cx = h // 2, w // 2
    y, x = np.ogrid[:h, :w]
    dist = np.sqrt((x - cx) ** 2 + (y - cy) ** 2)

    # 1. GAN Up-sampling Grid Artifacts: Peak-to-Average Power Ratio (PAPR)
    # Exclude DC center component (dist <= 4)
    ac_mask = dist > 4
    ac_mag = magnitude[ac_mask]
    if len(ac_mag) > 0:
        median_mag = max(0.5, float(np.median(ac_mag)))
        p99_mag = float(np.percentile(ac_mag, 99.5))
        papr = p99_mag / median_mag
        # Natural images exhibit smooth 1/f power falloff (PAPR < 5.0); GAN upsampling grid produces sharp spikes (PAPR > 6.0)
        gan_score = min(100.0, max(0.0, (papr - 5.0) * 18.0))
        gan_detected = gan_score >= 45.0
    else:
        gan_score = 0.0
        gan_detected = False
    
    # 2. Diffusion Spectral Power Density Slope
    mf_mask = (dist > min(h, w) * 0.1) & (dist < min(h, w) * 0.25)
    hf_mask = (dist >= min(h, w) * 0.25)
    
    mf_density = float(np.mean(magnitude[mf_mask])) if np.any(mf_mask) else 1.0
    hf_density = float(np.mean(magnitude[hf_mask])) if np.any(hf_mask) else 0.0
    
    # Natural images have steep 1/f roll-off (density_ratio < 0.45).
    # Iterative diffusion denoising introduces elevated high-frequency plateau (density_ratio > 0.65).
    density_ratio = hf_density / (mf_density + 1e-6)
    diffusion_score = min(100.0, max(0.0, (density_ratio - 0.45) * 180.0))
    
    return gan_detected, round(gan_score, 2), round(diffusion_score, 2)


def scan_ai_metadata(raw_bytes: bytes, pil_img: Optional[Image.Image]) -> Dict[str, Any]:
    meta = {
        "generator": None,
        "parameters": {},
        "c2pa_manifest_detected": False,
        "c2pa_markers": [],
        "ai_metadata_mentions": [],
    }

    # Structural / binary C2PA markers — definitive provenance manifest signatures
    STRUCTURAL_C2PA = [b"c2pa", b"C2PA", b"urn:c2pa", b"jumb", b"Adobe Content Authenticity"]
    # Brand-name strings in metadata
    BRAND_C2PA = [b"OpenAI", b"Midjourney", b"DALL-E", b"StableDiffusion", b"NovelAI"]
    CONTEXT_CHARS = set(b'"\'<>={};,')  # characters that suggest a structured context

    for sig in STRUCTURAL_C2PA:
        if sig in raw_bytes:
            meta["c2pa_manifest_detected"] = True
            name = sig.decode("ascii", errors="ignore")
            if name not in meta["c2pa_markers"]:
                meta["c2pa_markers"].append(name)

    for sig in BRAND_C2PA:
        idx = raw_bytes.find(sig)
        while idx != -1:
            before = raw_bytes[max(0, idx - 1): idx]
            after = raw_bytes[idx + len(sig): idx + len(sig) + 1]
            if (before and before[0] in CONTEXT_CHARS) or (after and after[0] in CONTEXT_CHARS):
                brand_name = sig.decode("ascii", errors="ignore")
                if brand_name not in meta["ai_metadata_mentions"]:
                    meta["ai_metadata_mentions"].append(brand_name)
                if not meta["generator"]:
                    meta["generator"] = brand_name
                break
            idx = raw_bytes.find(sig, idx + 1)

    if pil_img and hasattr(pil_img, "info") and pil_img.info:
        for k, v in pil_img.info.items():
            if str(k).lower() in ["parameters", "prompt", "workflow", "generation_data", "sd-metadata"]:
                meta["generator"] = "Stable Diffusion / ComfyUI"
                meta["parameters"][str(k)] = str(v)[:500]

    if not meta["generator"] and raw_bytes:
        raw_head = raw_bytes[:32768].decode("latin-1", errors="ignore")
        raw_tail = raw_bytes[-32768:].decode("latin-1", errors="ignore")
        combined_text = raw_head + " " + raw_tail

        if "parameters:" in combined_text or ("Steps:" in combined_text and "Sampler:" in combined_text) or "Negative prompt:" in combined_text:
            meta["generator"] = "Stable Diffusion"
            for pat, label in AI_METADATA_PATTERNS:
                match = re.search(rf"{pat}:\s*([^,\n]+)", combined_text, re.IGNORECASE)
                if match:
                    meta["parameters"][label] = match.group(1).strip()

    return meta


def analyze_noise_floor_consistency(pil_img: Image.Image) -> Tuple[bool, float]:
    """Estimate high-frequency noise floor consistency and inter-channel correlation.

    NOTE: Without a known physical camera reference sensor, this does NOT compute a true
    device-specific PRNU fingerprint. Instead, it measures inter-channel high-frequency
    residual noise correlation and spatial variance consistency. Real optical photography
    exhibits natural cross-channel noise correlation (0.25–0.70), whereas synthetic/diffusion
    images frequently exhibit an unnatural noise floor or synthetic smoothness.

    Returns: (sensor_noise_detected: bool, sensor_score: float [0-100])
    """
    try:
        rgb = np.array(pil_img.convert("RGB"), dtype=np.float32)
        h, w, c = rgb.shape
        if h < 64 or w < 64:
            return False, 50.0

        # Extract high-frequency noise residual per channel by subtracting local 3x3 mean
        residuals = []
        for ch in range(3):
            ch_data = rgb[:, :, ch]
            padded = np.pad(ch_data, 1, mode="edge")
            local_mean = (
                padded[:-2, :-2] + padded[:-2, 1:-1] + padded[:-2, 2:] +
                padded[1:-1, :-2] + padded[1:-1, 1:-1] + padded[1:-1, 2:] +
                padded[2:, :-2] + padded[2:, 1:-1] + padded[2:, 2:]
            ) / 9.0
            residual = ch_data - local_mean
            residuals.append(residual)

        r_res, g_res, b_res = residuals
        r_flat, g_flat, b_flat = r_res.flatten()[::10], g_res.flatten()[::10], b_res.flatten()[::10]

        if np.std(r_flat) < 1e-4 or np.std(g_flat) < 1e-4 or np.std(b_flat) < 1e-4:
            # Completely flat/synthetic surface, no sensor noise present
            return False, 0.0

        # Compute cross-channel Pearson correlation of high-frequency noise
        corr_rg = float(np.corrcoef(r_flat, g_flat)[0, 1])
        corr_gb = float(np.corrcoef(g_flat, b_flat)[0, 1])

        if np.isnan(corr_rg) or np.isnan(corr_gb):
            return False, 0.0

        avg_corr = (abs(corr_rg) + abs(corr_gb)) / 2.0
        # Physical camera sensors exhibit positive cross-channel noise correlation (usually 0.25 - 0.70)
        sensor_score = min(100.0, max(0.0, avg_corr * 150.0))
        sensor_present = sensor_score > 35.0
        return sensor_present, round(sensor_score, 2)
    except Exception:
        return False, 50.0


# Backward compatibility alias
analyze_prnu_sensor_noise = analyze_noise_floor_consistency


def detect_inpainting_anomalies(pil_img: Image.Image) -> float:
    """Detect regional inpainting / localized generative anomalies across image patches."""
    try:
        gray = np.array(pil_img.convert("L"), dtype=np.float32)
        h, w = gray.shape
        patch_size = 64
        if h < patch_size * 2 or w < patch_size * 2:
            return 0.0

        # Compute gradient magnitude
        gx = gray[:, 1:] - gray[:, :-1]
        gy = gray[1:, :] - gray[:-1, :]
        min_h, min_w = min(gx.shape[0], gy.shape[0]), min(gx.shape[1], gy.shape[1])
        grad_mag = np.sqrt(gx[:min_h, :min_w]**2 + gy[:min_h, :min_w]**2)

        variances = []
        for y in range(0, min_h - patch_size, patch_size):
            for x in range(0, min_w - patch_size, patch_size):
                patch = grad_mag[y:y+patch_size, x:x+patch_size]
                variances.append(float(np.var(patch)))

        if len(variances) < 4:
            return 0.0

        var_array = np.array(variances)
        # Robust percentile ratio to prevent flat-field false positive spikes
        p95_var = float(np.percentile(var_array, 95))
        median_var = max(15.0, float(np.median(var_array)))
        ratio = p95_var / median_var

        # Inpainted regions exhibit severe local variance discrepancy
        anomaly_score = min(100.0, max(0.0, (ratio - 3.5) * 15.0))
        return round(anomaly_score, 2)
    except Exception:
        return 0.0


def analyze_ai_generation(
    raw_bytes: bytes,
    pil_img: Optional[Image.Image],
    generate_visuals: bool = True,
) -> AIDetectionReport:
    rep = AIDetectionReport()
    meta = scan_ai_metadata(raw_bytes, pil_img)
    rep.ai_generator_detected = meta["generator"] is not None
    rep.ai_generator_name = meta["generator"]
    rep.prompt_parameters = meta["parameters"]
    rep.c2pa_present = meta["c2pa_manifest_detected"]
    rep.c2pa_markers = meta["c2pa_markers"]

    if rep.ai_generator_detected:
        rep.findings.append(f"Definitive AI generation metadata discovered: {rep.ai_generator_name}.")

    if rep.c2pa_present:
        markers_str = ", ".join(rep.c2pa_markers)
        rep.findings.append(f"Content Credentials / Provenance signatures present: {markers_str}.")

    if pil_img:
        try:
            vis, score, peak_ratio, ai_susp = calculate_fft_spectrum(pil_img)
            rep.fft_analyzed = True
            rep.fft_spectral_score = score
            rep.fft_peak_ratio = peak_ratio
            if generate_visuals:
                rep.fft_b64_image = numpy_to_base64_png(vis)
            if ai_susp:
                rep.findings.append(f"2D FFT Frequency Analysis reveals periodic grid spikes (Score: {score}/100.0).")

            gray = np.array(pil_img.convert("L"), dtype=np.float32)
            gan_det, gan_score, diff_score = analyze_gan_fingerprint(gray)
            rep.gan_fingerprint_detected = gan_det
            rep.gan_fingerprint_score = gan_score
            rep.diffusion_artifact_score = diff_score

            if gan_det:
                rep.findings.append(f"GAN upsampling fingerprint detected (Score: {gan_score}/100.0).")
            if diff_score > 60.0:
                rep.findings.append(f"Diffusion model high-frequency noise signature detected (Score: {diff_score}/100.0).")

            # Noise Floor Consistency (PRNU proxy) Analysis
            prnu_present, prnu_score = analyze_noise_floor_consistency(pil_img)
            rep.prnu_sensor_noise_detected = prnu_present
            rep.prnu_sensor_score = prnu_score
            if not prnu_present and not rep.c2pa_present and (rep.fft_spectral_score > 40 or diff_score > 40):
                rep.findings.append(f"Physical camera sensor noise floor absent (Score: {prnu_score}/100). Synthetic origin suspected.")

            # Inpainting Anomaly Detection
            inpainting_score = detect_inpainting_anomalies(pil_img)
            rep.inpainting_anomaly_score = inpainting_score
            if inpainting_score > 50.0:
                rep.findings.append(f"Regional generative inpainting anomaly detected (Discrepancy Score: {inpainting_score}/100.0).")

        except Exception as e:
            rep.findings.append(f"FFT/GAN/PRNU error: {str(e)}")

    if rep.ai_generator_detected:
        rep.is_ai_generated, rep.ai_probability_score, rep.ai_verdict = True, 100.0, "CONFIRMED_AI"
    else:
        # Multi-factor calibrated composite heuristic:
        fft_s = rep.fft_spectral_score
        gan_s = getattr(rep, "gan_fingerprint_score", 0.0)
        diff_s = getattr(rep, "diffusion_artifact_score", 0.0)
        inp_s = getattr(rep, "inpainting_anomaly_score", 0.0)

        composite = (fft_s * 0.40) + (gan_s * 0.30) + (diff_s * 0.20) + (inp_s * 0.10)
        if not rep.prnu_sensor_noise_detected and rep.prnu_sensor_score < 20.0 and composite > 30.0:
            composite += 10.0

        rep.ai_probability_score = round(min(100.0, max(0.0, composite)), 2)

        if rep.ai_probability_score >= 65.0:
            rep.is_ai_generated = True
            rep.ai_verdict = "HIGH_PROBABILITY_AI"
        elif rep.ai_probability_score >= 35.0:
            rep.is_ai_generated = False
            rep.ai_verdict = "SUSPICIOUS_HEURISTIC"
        else:
            rep.is_ai_generated = False
            rep.ai_verdict = "ORGANIC_NATURAL"

    return rep
