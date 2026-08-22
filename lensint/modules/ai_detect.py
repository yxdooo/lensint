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


def scan_ai_metadata(raw_bytes: bytes, pil_img: Optional[Image.Image]) -> Dict[str, Any]:
    meta = {
        "generator": None,
        "parameters": {},
        "c2pa_manifest_detected": False,
        "c2pa_markers": [],
    }

    for sig in C2PA_SIGNATURES:
        if sig in raw_bytes:
            meta["c2pa_manifest_detected"] = True
            name = sig.decode("ascii", errors="ignore")
            if name not in meta["c2pa_markers"]:
                meta["c2pa_markers"].append(name)

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
        except Exception as e:
            rep.findings.append(f"FFT error: {str(e)}")

    if rep.ai_generator_detected:
        rep.is_ai_generated, rep.ai_probability_score, rep.ai_verdict = True, 100.0, "CONFIRMED_AI"
    elif rep.fft_spectral_score >= 65.0:
        rep.is_ai_generated, rep.ai_probability_score, rep.ai_verdict = True, rep.fft_spectral_score, "HIGH_PROBABILITY_AI"
    else:
        rep.is_ai_generated, rep.ai_probability_score, rep.ai_verdict = False, max(0.0, rep.fft_spectral_score), "ORGANIC_NATURAL"

    return rep
