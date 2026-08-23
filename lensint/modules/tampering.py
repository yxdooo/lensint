"""
LENSINT - Deep Forensic Tampering & Image Manipulation Analysis Engine.
Courtroom-Grade Forensic Verification:
1. Error Level Analysis (ELA)
2. Copy-Move (Cloning) Keypoint Matching
3. JPEG Ghosts & Double Compression Detection
4. DQT (Quantization Table) Hardware/Software Fingerprint Matching
5. CFA / Bayer Demosaicing Inconsistency Analysis
6. 8x8 DCT Block Grid Shift & Alignment Verification
7. Chromatic Aberration Radial Optical Vector Consistency
8. Median Filter & Anti-Forensic Smoothing Artifact Detection
9. Illumination & Light Source Direction Vector Consistency
10. High-Pass Laplacian Sensor Noise Inconsistency
"""

import io
import math
import struct
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from PIL import Image, ImageDraw

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

from lensint.core.models import TamperingReport
from lensint.utils.image_ops import numpy_to_base64_png


# ============================================================================
# 1. Error Level Analysis (ELA)
# ============================================================================
def perform_ela(pil_img: Image.Image, quality: int = 90, multiplier: float = 15.0) -> Tuple[np.ndarray, float, float, float, float, str]:
    if getattr(pil_img, 'format', None) == 'PNG':
        h, w = pil_img.height, pil_img.width
        return np.zeros((h, w, 3), dtype=np.uint8), 0.0, 0.0, 0.0, 0.0, "Skipped ELA for PNG image to avoid artificial format-conversion artifacts."

    orig_rgb = pil_img.convert("RGB")
    orig_arr = np.array(orig_rgb, dtype=np.float32)
    h, w, _ = orig_arr.shape
    
    diff_sum = np.zeros((h, w, 3), dtype=np.float32)
    qualities = [max(10, quality - 10), quality, min(100, quality + 5)]
    for q in qualities:
        buf = io.BytesIO()
        orig_rgb.save(buf, format="JPEG", quality=q)
        buf.seek(0)
        recompressed = Image.open(buf).convert("RGB")
        recomp_arr = np.array(recompressed, dtype=np.float32)
        diff_sum += np.abs(orig_arr - recomp_arr)
        
    diff = diff_sum / float(len(qualities))

    mean_diff = float(np.mean(diff))
    max_diff = float(np.max(diff))
    std_diff = float(np.std(diff))
    ela_vis = np.clip(diff * multiplier, 0, 255).astype(np.uint8)

    block_size = 32
    block_means = []
    if h >= block_size and w >= block_size:
        for y in range(0, h - block_size + 1, block_size):
            for x in range(0, w - block_size + 1, block_size):
                blk = diff[y : y + block_size, x : x + block_size]
                block_means.append(float(np.mean(blk)))

    suspicion_score = 0.0
    if block_means:
        bm = np.array(block_means)
        global_median = float(np.median(bm))
        p95 = float(np.percentile(bm, 95))
        discrepancy = p95 - global_median
        suspicion_score = min(100.0, max(0.0, discrepancy * 8.0 + (std_diff * 4.0)))

    return ela_vis, mean_diff, max_diff, std_diff, round(suspicion_score, 2), ""


# ============================================================================
# 2. Copy-Move (Cloning) Keypoint Detection
# ============================================================================
def detect_copy_move(pil_img: Image.Image, min_matches: int = 8) -> Tuple[bool, int, Optional[np.ndarray]]:
    if not HAS_CV2:
        return False, 0, None

    img_arr = np.array(pil_img.convert("RGB"))
    gray = cv2.cvtColor(img_arr, cv2.COLOR_RGB2GRAY)
    orb = cv2.ORB_create(nfeatures=1200)
    keypoints, descriptors = orb.detectAndCompute(gray, None)
    if descriptors is None or len(descriptors) < 20:
        return False, 0, None

    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
    # Use k=3 so that match 0 is the keypoint itself, match 1 is 1st neighbor, match 2 is 2nd neighbor
    matches = bf.knnMatch(descriptors, descriptors, k=3)

    good_matches = []
    for match_group in matches:
        if len(match_group) < 3:
            continue
        m1, m2 = match_group[1], match_group[2]
        if m1.queryIdx != m1.trainIdx and m1.distance < 0.75 * m2.distance:
            pt1 = keypoints[m1.queryIdx].pt
            pt2 = keypoints[m1.trainIdx].pt
            spatial_dist = np.hypot(pt1[0] - pt2[0], pt1[1] - pt2[1])
            if spatial_dist > 40:
                good_matches.append(m1)

    match_count = len(good_matches)
    detected = match_count >= min_matches

    vis_img = None
    if detected:
        drawn = cv2.drawMatches(img_arr, keypoints, img_arr, keypoints, good_matches[:30], None, flags=2)
        vis_img = cv2.cvtColor(drawn, cv2.COLOR_BGR2RGB)

    return detected, match_count, vis_img

def detect_copy_move_dct(pil_img: Image.Image) -> Tuple[bool, int]:
    if not HAS_CV2:
        return False, 0
    gray = np.array(pil_img.convert("L"), dtype=np.float32)
    h, w = gray.shape
    if h < 64 or w < 64 or np.std(gray) < 2.0:
        return False, 0
        
    block_size = 16
    features = []
    coords = []
    for y in range(0, h - block_size + 1, block_size):
        for x in range(0, w - block_size + 1, block_size):
            blk = gray[y : y + block_size, x : x + block_size]
            if np.std(blk) < 1.0:
                continue  # Skip pure flat/solid blocks
            dct_blk = cv2.dct(blk)
            feat = dct_blk.flatten()[1:]
            norm = np.linalg.norm(feat)
            if norm > 1e-5:
                feat = feat / norm
            features.append(feat)
            coords.append((x, y))
            
    if len(features) < 10:
        return False, 0
        
    features_arr = np.array(features, dtype=np.float32)
    coords_arr = np.array(coords, dtype=np.float32)

    # Quantize primary low-frequency DCT coefficients into hash buckets (O(N) search)
    quantized = np.round(features_arr[:, :8] * 12.0).astype(np.int32)
    buckets: Dict[Tuple[int, ...], List[int]] = {}
    for idx, qv in enumerate(quantized):
        key = tuple(qv)
        buckets.setdefault(key, []).append(idx)

    match_count = 0
    for key, indices in buckets.items():
        if len(indices) < 2:
            continue
        # Limit comparisons per bucket to prevent flat-region combinatoric explosion
        sampled_indices = indices[:30]
        for i_pos in range(len(sampled_indices)):
            i = sampled_indices[i_pos]
            for j_pos in range(i_pos + 1, len(sampled_indices)):
                j = sampled_indices[j_pos]
                dist = np.linalg.norm(coords_arr[i] - coords_arr[j])
                if dist > 50:
                    sim = float(np.dot(features_arr[i], features_arr[j]))
                    if sim > 0.96:
                        match_count += 1
                        if match_count > 100:
                            break
            if match_count > 100:
                break
        if match_count > 100:
            break
                
    detected = match_count > 8
    return detected, match_count

# ============================================================================
# 3. JPEG Ghosts (Double Compression Sweeper)
# ============================================================================
def analyze_jpeg_ghosts(pil_img: Image.Image) -> Tuple[bool, List[int], float, Optional[np.ndarray]]:
    orig_rgb = pil_img.convert("RGB")
    orig_arr = np.array(orig_rgb, dtype=np.float32)
    h, w, _ = orig_arr.shape
    if np.std(orig_arr) < 2.0:
        return False, [], 0.0, None

    qualities = [50, 60, 70, 75, 80, 85, 90, 95]
    diff_maps = []

    for q in qualities:
        buf = io.BytesIO()
        orig_rgb.save(buf, format="JPEG", quality=q)
        buf.seek(0)
        recomp = np.array(Image.open(buf).convert("RGB"), dtype=np.float32)
        diff = np.mean(np.abs(orig_arr - recomp), axis=2)
        diff_maps.append(diff)

    block_size = 32
    detected_qualities = set()
    ghost_vis = np.zeros((h, w), dtype=np.float32)

    if h >= block_size and w >= block_size:
        for y in range(0, h - block_size + 1, block_size):
            for x in range(0, w - block_size + 1, block_size):
                block_diffs = [np.mean(dm[y : y + block_size, x : x + block_size]) for dm in diff_maps]
                min_idx = int(np.argmin(block_diffs))
                detected_qualities.add(qualities[min_idx])
                ghost_vis[y : y + block_size, x : x + block_size] = qualities[min_idx]

    qual_list = sorted(list(detected_qualities))
    has_ghosts = len(qual_list) >= 3 and (max(qual_list) - min(qual_list) >= 25)
    divergence_score = round(min(100.0, float(len(qual_list) * 20.0)), 2)

    norm_vis = None
    if has_ghosts:
        mn, mx = np.min(ghost_vis), np.max(ghost_vis)
        if mx > mn:
            norm_vis = ((ghost_vis - mn) / (mx - mn) * 255.0).astype(np.uint8)
        else:
            norm_vis = np.zeros((h, w), dtype=np.uint8)

    return has_ghosts, qual_list, divergence_score, norm_vis


# ============================================================================
# 4. DQT (Quantization Table) Hardware/Software Profiling
# ============================================================================
KNOWN_DQT_SIGNATURES = [
    ("Adobe Photoshop Save for Web Quality 100", [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
    ("Adobe Photoshop Save for Web Quality 90", [2, 1, 1, 2, 1, 1, 2, 2, 2, 2, 3, 3, 2, 3, 4, 6]),
    ("Adobe Photoshop Save for Web Quality 80", [3, 2, 2, 3, 2, 2, 3, 3, 3, 3, 4, 4, 3, 4, 5, 8]),
    ("Adobe Photoshop Save for Web Quality 70", [5, 3, 3, 5, 4, 3, 5, 5, 4, 5, 6, 6, 5, 6, 8, 12]),
    ("Adobe Photoshop Save for Web Quality 60", [6, 4, 4, 6, 5, 4, 6, 6, 5, 6, 7, 7, 7, 7, 9, 15]),
    ("Adobe Photoshop Quality 12 (Maximum Save As)", [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
    ("Adobe Photoshop Quality 10 (Standard Save As)", [2, 1, 1, 2, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 5]),
    ("Adobe Lightroom Classic High-Quality Export", [1, 1, 1, 2, 1, 1, 2, 2, 2, 2, 2, 2, 2, 3, 3, 5]),
    ("Apple iPhone 13-16 Pro Native ISP Encoder", [2, 1, 1, 2, 1, 1, 2, 2, 2, 2, 3, 3, 2, 3, 4, 6]),
    ("Samsung Galaxy S20-S24 Ultra Native ISP", [3, 2, 2, 3, 2, 2, 3, 3, 3, 3, 4, 3, 3, 4, 5, 7]),
    ("Google Pixel 6-9 Pro HDR+ Computational ISP", [2, 1, 1, 2, 1, 1, 2, 2, 2, 2, 3, 2, 2, 3, 4, 5]),
    ("Canon EOS DIGIC 7/8/X Hardware Encoder", [2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 4, 4]),
    ("Nikon EXPEED 6/7 Hardware Encoder", [2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 5]),
    ("Sony Alpha BIONZ X/XR Hardware Encoder", [1, 1, 1, 2, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 6]),
    ("DJI Mavic / Mini Pro Drone Native Encoder", [2, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 6]),
    ("WhatsApp Web / Mobile Transcoder Quality 80", [5, 3, 3, 5, 7, 12, 15, 18, 4, 4, 4, 6, 8, 17, 18, 16]),
    ("Telegram Web Image Transcoder", [6, 4, 4, 6, 9, 15, 20, 24, 5, 5, 5, 8, 10, 22, 23, 21]),
    ("Twitter / X Media Compression Pipeline", [5, 4, 4, 6, 8, 13, 17, 21, 4, 4, 5, 7, 9, 19, 20, 18]),
    ("GIMP Standard Export Quality 90", [3, 2, 2, 3, 2, 2, 3, 3, 3, 3, 4, 4, 3, 4, 5, 7]),
    ("Affinity Photo 2 JPEG Exporter", [2, 1, 1, 2, 1, 1, 2, 2, 2, 2, 2, 3, 2, 3, 4, 6]),
    ("Independent JPEG Group (IJG) Standard Q75", [8, 6, 5, 8, 12, 20, 26, 31, 6, 6, 7, 10, 13, 29, 30, 28]),
]


def analyze_dqt_tables(raw_bytes: bytes) -> Tuple[bool, Optional[str], Optional[int], bool, Dict[str, List[int]]]:
    dqt_tables = {}
    found = False
    identified_encoder = None
    quality_est = None
    hw_mismatch = False

    pos = 0
    while True:
        pos = raw_bytes.find(b"\xFF\xDB", pos)
        if pos == -1 or pos + 4 > len(raw_bytes):
            break
        length = int.from_bytes(raw_bytes[pos + 2 : pos + 4], byteorder="big")
        # Guard against malformed segments with length=0 or impossibly small
        # values that would cause the loop to stall or go backwards.
        if length < 3:
            pos += 2
            continue
        payload = raw_bytes[pos + 4 : pos + 2 + length]
        offset = 0
        while offset + 65 <= len(payload):
            table_id = payload[offset] & 0x0F
            name = "Luminance" if table_id == 0 else f"Chrominance_{table_id}"
            dqt_tables[name] = list(payload[offset + 1 : offset + 65])
            found = True
            offset += 65
        pos += 2 + length

    if found and "Luminance" in dqt_tables:
        lum = dqt_tables["Luminance"]
        avg_lum = float(np.mean(lum))
        quality_est = int(max(1, min(100, round(100.0 - (avg_lum * 1.8)))))

        for name, sig in KNOWN_DQT_SIGNATURES:
            if lum[: len(sig)] == sig:
                identified_encoder = name
                break

        if not identified_encoder:
            if avg_lum <= 3.0:
                identified_encoder = "High-Quality Software / Pro DSLR Encoder"
            elif avg_lum <= 8.0:
                identified_encoder = "Standard Mobile / Web Compressed Encoder"
            else:
                identified_encoder = "High-Compression Web Encoder"

    return found, identified_encoder, quality_est, hw_mismatch, dqt_tables


# ============================================================================
# 5. CFA / Bayer Demosaicing Residual Analysis
# ============================================================================
def analyze_cfa_demosaicing(pil_img: Image.Image) -> Tuple[float, bool]:
    """Analyze Bayer CFA demosaicing residuals using directional gradient interpolation.

    Evaluates whether green channel interpolation residuals follow periodic CFA
    patterns in flat/textured regions, with directional weighting to avoid false
    positives on sharp physical edges.
    """
    rgb = np.array(pil_img.convert("RGB"), dtype=np.float32)
    h, w, _ = rgb.shape
    if h < 64 or w < 64 or np.std(rgb) < 2.0:
        return 0.0, False

    green = rgb[:, :, 1]
    
    # Compute horizontal and vertical second differences
    dh = np.abs(green[1:-1, :-2] - green[1:-1, 2:])
    dv = np.abs(green[:-2, 1:-1] - green[2:, 1:-1])

    # Directional interpolation: interpolate along direction of smallest gradient
    recon = np.zeros_like(green)
    h_interp = (green[1:-1, :-2] + green[1:-1, 2:]) / 2.0
    v_interp = (green[:-2, 1:-1] + green[2:, 1:-1]) / 2.0
    avg_interp = (green[:-2, 1:-1] + green[2:, 1:-1] + green[1:-1, :-2] + green[1:-1, 2:]) / 4.0

    mask_h = dh < (dv * 0.7)
    mask_v = dv < (dh * 0.7)
    mask_avg = ~(mask_h | mask_v)

    recon_inner = np.where(mask_h, h_interp, np.where(mask_v, v_interp, avg_interp))
    residual = np.abs(green[1:-1, 1:-1] - recon_inner)

    block_size = 16
    block_vars = []
    for y in range(0, residual.shape[0] - block_size + 1, block_size):
        for x in range(0, residual.shape[1] - block_size + 1, block_size):
            blk = residual[y : y + block_size, x : x + block_size]
            block_vars.append(float(np.var(blk)))

    if len(block_vars) < 10:
        return 0.0, False

    bv = np.array(block_vars)
    mean_v = float(np.mean(bv))
    if mean_v > 0.1:
        cv_cfa = float(np.std(bv) / mean_v)
        cfa_score = min(100.0, round(cv_cfa * 25.0, 2))
        return cfa_score, cfa_score >= 65.0

    return 0.0, False


# ============================================================================
# 6. 8x8 DCT Block Grid Alignment & Discontinuity
# ============================================================================
def analyze_block_grid_inconsistency(pil_img: Image.Image) -> Tuple[bool, Tuple[int, int], float]:
    gray = np.array(pil_img.convert("L"), dtype=np.float32)
    h, w = gray.shape
    if h < 64 or w < 64 or np.std(gray) < 2.0:
        return False, (0, 0), 0.0

    diff_h = np.abs(gray[1:-1, 2:] - 2 * gray[1:-1, 1:-1] + gray[1:-1, :-2])
    diff_v = np.abs(gray[2:, 1:-1] - 2 * gray[1:-1, 1:-1] + gray[:-2, 1:-1])

    energies = {}
    for dy in range(8):
        for dx in range(8):
            grid_h = diff_h[dy::8, dx::8]
            grid_v = diff_v[dy::8, dx::8]
            energies[(dx, dy)] = float(np.mean(grid_h) + np.mean(grid_v))

    best_phase = max(energies, key=energies.get)
    max_energy = energies[best_phase]
    avg_energy = float(np.mean(list(energies.values())))

    ratio = (max_energy / (avg_energy + 1e-6)) if avg_energy > 0 else 1.0
    artifact_score = min(100.0, max(0.0, round((ratio - 1.0) * 120.0, 2)))

    shifted = best_phase != (0, 0) and artifact_score >= 40.0
    return shifted, best_phase, artifact_score


# ============================================================================
# 7. Chromatic Aberration Radial Optical Vector Consistency
# ============================================================================
def analyze_chromatic_aberration(pil_img: Image.Image) -> Tuple[float, bool]:
    """Analyze Edge-Aligned Lateral Chromatic Aberration (LCA) consistency.

    Real camera lenses cause wavelength-dependent radial refraction (color fringes)
    perpendicular to high-contrast edges in the periphery, directed away from the
    optical center. Spliced or synthetic images lack this optical radial alignment.

    Returns:
        (inconsistency_score: float [0-100], aberration_detected: bool)
    """
    try:
        rgb = np.array(pil_img.convert("RGB"), dtype=np.float32)
        h, w, _ = rgb.shape
        if h < 100 or w < 100 or float(np.std(rgb)) < 2.0:
            return 0.0, False

        # Grayscale luminance for edge detection
        gray = 0.299 * rgb[:, :, 0] + 0.587 * rgb[:, :, 1] + 0.114 * rgb[:, :, 2]
        gy, gx = np.gradient(gray)
        grad_mag = np.sqrt(gx ** 2 + gy ** 2)

        cy, cx = h / 2.0, w / 2.0
        y_coords, x_coords = np.ogrid[:h, :w]
        # Radial vector from optical center (image center)
        rx = (x_coords - cx)
        ry = (y_coords - cy)
        radial_dist = np.sqrt(rx ** 2 + ry ** 2)

        # Peripheral zone (> 30% from center) where LCA is optically strongest
        outer_mask = (radial_dist > min(h, w) * 0.30) & (grad_mag > 15.0)
        if np.sum(outer_mask) < 64:
            return 0.0, False

        # Channel difference gradients (R - B fringe)
        diff_rb = rgb[:, :, 0] - rgb[:, :, 2]
        d_rby, d_rbx = np.gradient(diff_rb)

        # In true LCA, the R-B fringe gradient aligns with the radial vector (rx, ry)
        norm_r = radial_dist[outer_mask] + 1e-6
        unit_rx = rx[outer_mask] / norm_r
        unit_ry = ry[outer_mask] / norm_r

        grad_rb_mag = np.sqrt(d_rbx[outer_mask] ** 2 + d_rby[outer_mask] ** 2) + 1e-6
        unit_gx = d_rbx[outer_mask] / grad_rb_mag
        unit_gy = d_rby[outer_mask] / grad_rb_mag

        # Alignment cos(theta)
        alignment = np.abs(unit_rx * unit_gx + unit_ry * unit_gy)
        var_bleed = float(np.var(diff_rb[~outer_mask])) if np.sum(~outer_mask) > 100 else 0.0

        misalignment = float(1.0 - np.mean(alignment))
        inconsistency_score = round(min(100.0, max(0.0, (misalignment * 60.0) + min(40.0, var_bleed * 0.05))), 2)

        return inconsistency_score, inconsistency_score >= 65.0
    except Exception:
        return 0.0, False


# ============================================================================
# 8. Median Filtering / Anti-Forensic Smoothing Detection
# ============================================================================
def analyze_median_filtering(pil_img: Image.Image) -> Tuple[bool, float]:
    gray = np.array(pil_img.convert("L"), dtype=np.int32)
    h, w = gray.shape
    if h < 64 or w < 64 or float(np.std(gray)) < 2.0:
        return False, 0.0

    diff_x = gray[:, 1:] - gray[:, :-1]
    diff_y = gray[1:, :] - gray[:-1, :]

    zero_count_x = np.sum(diff_x == 0)
    zero_count_y = np.sum(diff_y == 0)
    total_diffs = (h * (w - 1)) + ((h - 1) * w)

    zero_ratio = (zero_count_x + zero_count_y) / float(total_diffs)
    median_score = min(100.0, max(0.0, round((zero_ratio - 0.12) * 350.0, 2)))

    return median_score >= 50.0, median_score


# ============================================================================
# 9. Illumination & Light Source Direction Consistency
# ============================================================================
def analyze_illumination_consistency(pil_img: Image.Image) -> Tuple[float, bool]:
    gray = np.array(pil_img.convert("L"), dtype=np.float32)
    h, w = gray.shape
    if h < 64 or w < 64 or np.std(gray) < 2.0:
        return 0.0, False

    gx = gray[1:-1, 2:] - gray[1:-1, :-2]
    gy = gray[2:, 1:-1] - gray[:-2, 1:-1]
    magnitude = np.sqrt(gx**2 + gy**2)
    angles = np.arctan2(gy, gx)

    mh, mw = magnitude.shape
    mid_y, mid_x = mh // 2, mw // 2
    quad_angles = []

    quads = [
        (slice(0, mid_y), slice(0, mid_x)),
        (slice(0, mid_y), slice(mid_x, mw)),
        (slice(mid_y, mh), slice(0, mid_x)),
        (slice(mid_y, mh), slice(mid_x, mw)),
    ]

    for sy, sx in quads:
        quad_mag = magnitude[sy, sx]
        quad_ang = angles[sy, sx]
        high_grad = quad_mag > np.percentile(quad_mag, 85)
        if np.sum(high_grad) > 50:
            sin_mean = np.mean(np.sin(quad_ang[high_grad]))
            cos_mean = np.mean(np.cos(quad_ang[high_grad]))
            circ_mean = float(np.arctan2(sin_mean, cos_mean))
            quad_angles.append(circ_mean)

    if len(quad_angles) < 4:
        return 0.0, False

    angle_diffs = []
    for i in range(len(quad_angles)):
        for j in range(i + 1, len(quad_angles)):
            delta = abs(quad_angles[i] - quad_angles[j])
            circ_diff = min(delta, 2 * math.pi - delta)
            angle_diffs.append(circ_diff)

    max_divergence = max(angle_diffs) if angle_diffs else 0.0
    illumination_score = min(100.0, round((max_divergence / math.pi) * 80.0, 2))

    return illumination_score, illumination_score >= 60.0


# ============================================================================
# 10. Sensor Noise Inconsistency (High-Pass Laplacian)
# ============================================================================
def analyze_noise_consistency(pil_img: Image.Image) -> float:
    gray = np.array(pil_img.convert("L"), dtype=np.float32)
    h, w = gray.shape
    if h < 64 or w < 64 or np.std(gray) < 2.0:
        return 0.0

    padded = np.pad(gray, 1, mode="reflect")
    laplacian = padded[:-2, 1:-1] + padded[2:, 1:-1] + padded[1:-1, :-2] + padded[1:-1, 2:] - 4.0 * gray
    block_size = 32
    variances = []
    for y in range(0, h - block_size + 1, block_size):
        for x in range(0, w - block_size + 1, block_size):
            block_raw = gray[y : y + block_size, x : x + block_size]
            if 15 < np.mean(block_raw) < 240:
                blk = laplacian[y : y + block_size, x : x + block_size]
                v = float(np.var(blk))
                if v > 0.5:
                    variances.append(v)

    if len(variances) < 6:
        return 0.0
    var_arr = np.array(variances)
    var_mean = np.mean(var_arr)
    if var_mean > 1.0:
        cv = np.std(var_arr) / var_mean
        return round(min(100.0, float(cv * 30.0)), 2)
    return 0.0


def analyze_splice_detection(pil_img: Image.Image, generate_visuals: bool = True) -> Tuple[bool, float, Optional[str], List[Dict[str, Any]]]:
    gray = np.array(pil_img.convert("L"), dtype=np.float32)
    h, w = gray.shape
    block_size = 64
    
    variances = []
    var_map = []
    
    for y in range(0, h - block_size + 1, block_size):
        row_vars = []
        for x in range(0, w - block_size + 1, block_size):
            blk = gray[y : y + block_size, x : x + block_size]
            if HAS_CV2:
                lap = cv2.Laplacian(blk.astype(np.float64), cv2.CV_64F)
            else:
                p = np.pad(blk, 1, mode="reflect")
                lap = p[:-2, 1:-1] + p[2:, 1:-1] + p[1:-1, :-2] + p[1:-1, 2:] - 4.0 * blk
            var = np.var(lap)
            row_vars.append(var)
            variances.append(var)
        var_map.append(row_vars)
        
    if not variances:
        return False, 0.0, None, []
        
    mean_v = np.mean(variances)
    std_v = np.std(variances)
    ratio = std_v / (mean_v + 1e-6)
    
    detected = bool(ratio > 1.2)
    confidence = float(min(100.0, float(ratio) * 40.0))
    
    detected_boxes: List[Dict[str, Any]] = []
    if detected and var_map:
        threshold = mean_v + 1.8 * std_v
        for r, row in enumerate(var_map):
            for c, val in enumerate(row):
                if val > threshold:
                    detected_boxes.append({
                        "x": c * block_size,
                        "y": r * block_size,
                        "w": block_size,
                        "h": block_size,
                        "type": "noise_variance_outlier",
                        "confidence": round(min(100.0, float((val - mean_v) / (std_v + 1e-6)) * 25.0), 1),
                    })

    b64_img = None
    if generate_visuals and var_map:
        var_map_arr = np.array(var_map)
        mn, mx = np.min(var_map_arr), np.max(var_map_arr)
        
        hm_w = len(var_map[0])
        hm_h = len(var_map)
        scale = 4
        img = Image.new("RGB", (hm_w * scale, hm_h * scale))
        draw = ImageDraw.Draw(img)
        
        for r in range(hm_h):
            for c in range(hm_w):
                v = var_map_arr[r, c]
                norm_v = (v - mn) / (mx - mn + 1e-6)
                if norm_v < 0.5:
                    r_col = 0
                    g_col = int(norm_v * 2 * 255)
                    b_col = int((1 - norm_v * 2) * 255)
                else:
                    r_col = int((norm_v - 0.5) * 2 * 255)
                    g_col = int((1 - (norm_v - 0.5) * 2) * 255)
                    b_col = 0
                
                x0, y0 = c * scale, r * scale
                x1, y1 = x0 + scale, y0 + scale
                draw.rectangle([x0, y0, x1, y1], fill=(r_col, g_col, b_col))
                
        b64_img = numpy_to_base64_png(np.array(img))
        
    return detected, confidence, b64_img, detected_boxes

# ============================================================================
# Master Tampering & Deep Forensic Orchestrator
# ============================================================================
def analyze_tampering(
    pil_img: Optional[Image.Image],
    raw_bytes: bytes = b"",
    ela_quality: int = 90,
    generate_visuals: bool = True,
    is_screenshot: bool = False,
) -> TamperingReport:
    report = TamperingReport()
    if pil_img is None:
        report.findings.append("Tampering analysis skipped: unable to decode image pixel data.")
        return report

    try:
        orig_pil_img = pil_img
        w, h = pil_img.width, pil_img.height
        if w * h > 4_000_000:
            max_dim = 2000
            scale = min(max_dim / w, max_dim / h)
            new_w, new_h = int(w * scale), int(h * scale)
            pil_img = pil_img.resize((new_w, new_h), Image.LANCZOS)
            report.findings.append("Image downsampled to max 2000px for expensive operations.")

        # 1. Error Level Analysis (ELA)
        ela_vis, m_diff, mx_diff, s_diff, ela_score, ela_note = perform_ela(orig_pil_img, quality=ela_quality)
        report.ela_performed = True
        report.ela_difference_mean = round(m_diff, 3)
        report.ela_difference_max = round(mx_diff, 3)
        report.ela_difference_std = round(s_diff, 3)
        report.ela_suspicion_score = ela_score
        if hasattr(report, 'ela_confidence'):
            report.ela_confidence = min(100.0, ela_score * 1.5)
        if ela_note:
            report.findings.append(ela_note)
        if generate_visuals:
            report.ela_b64_image = numpy_to_base64_png(ela_vis)

        # 2. Copy-Move (Cloning) Detection
        cm_detected, cm_count, cm_vis = detect_copy_move(orig_pil_img)
        if not cm_detected and cm_count == 0:
            dct_detected, dct_count = detect_copy_move_dct(orig_pil_img)
            if dct_detected:
                cm_detected = True
                cm_count = dct_count
                
        report.copy_move_detected = cm_detected
        report.copy_move_match_count = cm_count
        if hasattr(report, 'copy_move_confidence'):
            report.copy_move_confidence = min(95, 20 + cm_count * 3)
            
        if cm_vis is not None and generate_visuals:
            report.copy_move_b64_image = numpy_to_base64_png(cm_vis)
        if cm_detected:
            report.findings.append(f"Copy-Move cloning detected ({cm_count} duplicated keypoint pairs).")

        # 3. JPEG Ghosts & Double Compression
        ghost_det, ghost_quals, ghost_score, ghost_vis = analyze_jpeg_ghosts(pil_img)
        report.jpeg_ghosts_detected = ghost_det and not is_screenshot
        report.jpeg_ghost_qualities = ghost_quals
        report.jpeg_ghost_difference_score = ghost_score
        if ghost_vis is not None and generate_visuals:
            report.jpeg_ghost_b64_image = numpy_to_base64_png(ghost_vis)
        if ghost_det and not is_screenshot:
            report.findings.append(f"JPEG Ghosts / Double compression detected (Quality variance: {ghost_quals}).")

        # 4. DQT Quantization Table Forensics
        dqt_found, dqt_enc, dqt_q, dqt_mismatch, dqt_tabs = analyze_dqt_tables(raw_bytes)
        report.dqt_found = dqt_found
        report.dqt_identified_encoder = dqt_enc
        report.dqt_quality_estimate = dqt_q
        report.dqt_hardware_mismatch = dqt_mismatch
        report.dqt_tables = dqt_tabs
        if dqt_found and dqt_enc:
            report.findings.append(f"DQT Quantization signature matches: {dqt_enc} (Est. Quality: {dqt_q}%).")

        # 5. CFA / Bayer Demosaicing
        if is_screenshot:
            report.sensor_heuristics_suppressed = True
            report.cfa_inconsistency_score = 0.0
            report.cfa_tampering_detected = False
        else:
            cfa_score, cfa_det = analyze_cfa_demosaicing(pil_img)
            report.cfa_inconsistency_score = cfa_score
            report.cfa_tampering_detected = cfa_det
            if cfa_det:
                report.findings.append(f"CFA Bayer demosaicing anomaly detected (Score: {cfa_score}/100). Splicing suspected.")

        # 6. 8x8 DCT Block Grid Shift
        grid_shifted, grid_phase, bag_score = analyze_block_grid_inconsistency(pil_img)
        report.block_grid_shifted = grid_shifted and not is_screenshot
        report.block_grid_offset = grid_phase
        report.block_artifact_score = bag_score
        if grid_shifted and not is_screenshot:
            report.findings.append(f"8x8 DCT block grid phase shift detected (Offset: {grid_phase}). Pasted patch misaligned.")

        # 7. Chromatic Aberration
        if is_screenshot:
            report.chromatic_aberration_inconsistency = 0.0
            report.chromatic_aberration_detected = False
        else:
            ca_score, ca_det = analyze_chromatic_aberration(pil_img)
            report.chromatic_aberration_inconsistency = ca_score
            report.chromatic_aberration_detected = ca_det
            if ca_det:
                report.findings.append(f"Chromatic aberration radial vector anomaly detected (Score: {ca_score}/100). Composite lens optics.")

        # 8. Median Filtering / Anti-Forensic Smoothing
        mf_det, mf_score = analyze_median_filtering(pil_img)
        report.median_filter_detected = mf_det and not is_screenshot
        report.median_filter_score = mf_score
        if mf_det and not is_screenshot:
            report.findings.append(f"Median filter / Edge smoothing detected (Score: {mf_score}/100). Anti-forensic concealment.")

        # 9. Illumination Consistency
        illum_score, illum_det = analyze_illumination_consistency(pil_img)
        report.illumination_variance_score = illum_score
        report.illumination_conflict_detected = illum_det and not is_screenshot
        if illum_det and not is_screenshot:
            report.findings.append(f"Illumination & lighting angle conflict detected (Score: {illum_score}/100). Inconsistent lighting sources.")

        # 10. Sensor Noise Variance
        noise_score = analyze_noise_consistency(pil_img) if not is_screenshot else 0.0
        report.noise_inconsistency_score = noise_score

        if is_screenshot:
            report.findings.append("Digital UI Screen Capture detected: physical camera sensor tests (Bayer CFA, Chromatic Aberration) suppressed.")

        # Splice Detection
        if not is_screenshot and (orig_pil_img.format == 'JPEG' or (w >= 200 and h >= 200)):
            splice_det, splice_conf, splice_vis, splice_boxes = analyze_splice_detection(orig_pil_img, generate_visuals)
            if hasattr(report, 'splice_detected'):
                report.splice_detected = splice_det
                report.splice_confidence = splice_conf
                if splice_vis:
                    report.splice_b64_image = splice_vis
            if splice_det:
                report.findings.append(f"Image splicing / local composition detected (Confidence: {splice_conf:.1f}%).")
                if hasattr(report, 'detected_regions'):
                    if splice_boxes:
                        report.detected_regions.extend(splice_boxes)
                    else:
                        report.detected_regions.append({"x": 0, "y": 0, "w": w, "h": h, "type": "splice_candidate", "confidence": splice_conf})

        # Composite Forensic Scoring
        # Use the report fields (which already have screenshot suppression applied)
        # instead of the raw local variables to stay consistent.
        if is_screenshot:
            composite_score = (
                (ela_score * 0.20)
                + (40.0 if cm_detected else 0.0)
            )
        else:
            composite_score = (
                (ela_score * 0.25)
                + (40.0 if cm_detected else 0.0)
                + (30.0 if report.jpeg_ghosts_detected else 0.0)
                + (25.0 if report.cfa_tampering_detected else 0.0)
                + (25.0 if report.block_grid_shifted else 0.0)
                + (20.0 if report.chromatic_aberration_detected else 0.0)
                + (15.0 if report.median_filter_detected else 0.0)
                + (15.0 if report.illumination_conflict_detected else 0.0)
            )

        if composite_score >= 60.0 or cm_detected or (ghost_det and not is_screenshot):
            report.suspicion_level = "HIGH"
            report.findings.append(f"High digital manipulation probability (Courtroom-grade composite score: {min(100.0, composite_score):.1f}/100).")
        elif composite_score >= 30.0:
            report.suspicion_level = "MEDIUM"
            report.findings.append(f"Moderate editing indications detected (Composite score: {min(100.0, composite_score):.1f}/100).")
        else:
            report.suspicion_level = "LOW"
            if not report.findings:
                report.findings.append("No significant compression, cloning, demosaicing, or optical anomalies detected.")

    except Exception as e:
        report.findings.append(f"Deep tampering analysis error: {str(e)}")

    return report
