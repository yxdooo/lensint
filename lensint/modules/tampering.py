import io
from typing import Optional, Tuple
import numpy as np
from PIL import Image, ImageDraw

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

from lensint.core.models import TamperingReport
from lensint.utils.image_ops import numpy_to_base64_png

def perform_ela(pil_img: Image.Image, quality: int = 90, multiplier: float = 15.0) -> Tuple[np.ndarray, float, float, float, float]:
    orig_rgb = pil_img.convert('RGB')
    buf = io.BytesIO()
    orig_rgb.save(buf, format='JPEG', quality=quality)
    buf.seek(0)
    recompressed = Image.open(buf).convert('RGB')

    orig_arr = np.array(orig_rgb, dtype=np.float32)
    recomp_arr = np.array(recompressed, dtype=np.float32)
    diff = np.abs(orig_arr - recomp_arr)
    mean_diff = float(np.mean(diff))
    max_diff = float(np.max(diff))
    std_diff = float(np.std(diff))
    ela_vis = np.clip(diff * multiplier, 0, 255).astype(np.uint8)

    h, w, _ = diff.shape
    block_size = 32
    block_means = []
    if h >= block_size and w >= block_size:
        for y in range(0, h - block_size + 1, block_size):
            for x in range(0, w - block_size + 1, block_size):
                blk = diff[y : y + block_size, x : x + block_size]
                block_means.append(np.mean(blk))

    suspicion_score = 0.0
    if block_means:
        bm = np.array(block_means)
        global_median = float(np.median(bm))
        p95 = float(np.percentile(bm, 95))
        discrepancy = p95 - global_median
        suspicion_score = min(100.0, max(0.0, discrepancy * 8.0 + (std_diff * 4.0)))

    return ela_vis, mean_diff, max_diff, std_diff, round(suspicion_score, 2)


def analyze_noise_consistency(pil_img: Image.Image) -> float:
    gray = np.array(pil_img.convert('L'), dtype=np.float32)
    h, w = gray.shape
    if h < 64 or w < 64: return 0.0

    padded = np.pad(gray, 1, mode='reflect')
    laplacian = padded[:-2, 1:-1] + padded[2:, 1:-1] + padded[1:-1, :-2] + padded[1:-1, 2:] - 4.0 * gray
    block_size = 32
    variances = []
    for y in range(0, h - block_size + 1, block_size):
        for x in range(0, w - block_size + 1, block_size):
            block_raw = gray[y : y + block_size, x : x + block_size]
            if 15 < np.mean(block_raw) < 240:
                blk = laplacian[y : y + block_size, x : x + block_size]
                v = float(np.var(blk))
                if v > 0.5: variances.append(v)

    if len(variances) < 6: return 0.0
    var_arr = np.array(variances)
    var_mean = np.mean(var_arr)
    if var_mean > 1.0:
        cv = np.std(var_arr) / var_mean
        return round(min(100.0, float(cv * 30.0)), 2)
    return 0.0

def detect_copy_move(pil_img: Image.Image, min_matches: int = 8) -> Tuple[bool, int, Optional[np.ndarray]]:
    if not HAS_CV2:
        return False, 0, None

    img_arr = np.array(pil_img.convert('RGB'))
    gray = cv2.cvtColor(img_arr, cv2.COLOR_RGB2GRAY)
    orb = cv2.ORB_create(nfeatures=1200)
    keypoints, descriptors = orb.detectAndCompute(gray, None)
    if descriptors is None or len(descriptors) < 20:
        return False, 0, None

    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
    matches = bf.knnMatch(descriptors, descriptors, k=2)

    good_matches = []
    for m, n in matches:
        if m.queryIdx != m.trainIdx and m.distance < 0.75 * n.distance:
            pt1 = keypoints[m.queryIdx].pt
            pt2 = keypoints[m.trainIdx].pt
            spatial_dist = np.sqrt((pt1[0] - pt2[0]) ** 2 + (pt1[1] - pt2[1]) ** 2)
            if spatial_dist > 40:
                good_matches.append(m)

    match_count = len(good_matches)
    detected = match_count >= min_matches

    vis_img = None
    if detected:
        drawn = cv2.drawMatches(img_arr, keypoints, img_arr, keypoints, good_matches[:30], None, flags=2)
        vis_img = cv2.cvtColor(drawn, cv2.COLOR_BGR2RGB)

    return detected, match_count, vis_img


def analyze_tampering(pil_img: Optional[Image.Image], ela_quality: int = 90, generate_visuals: bool = True) -> TamperingReport:
    report = TamperingReport()
    if pil_img is None:
        report.findings.append('Tampering analysis skipped: unable to decode image pixel data.')
        return report

    try:
        ela_vis, m_diff, mx_diff, s_diff, ela_score = perform_ela(pil_img, quality=ela_quality)
        report.ela_performed = True
        report.ela_difference_mean = round(m_diff, 3)
        report.ela_difference_max = round(mx_diff, 3)
        report.ela_difference_std = round(s_diff, 3)
        report.ela_suspicion_score = ela_score
        if generate_visuals:
            report.ela_b64_image = numpy_to_base64_png(ela_vis)

        noise_score = analyze_noise_consistency(pil_img)
        report.noise_inconsistency_score = noise_score

        cm_detected, cm_count, cm_vis = detect_copy_move(pil_img)
        report.copy_move_detected = cm_detected
        report.copy_move_match_count = cm_count
        if cm_vis is not None and generate_visuals:
            report.copy_move_b64_image = numpy_to_base64_png(cm_vis)
        if cm_detected:
            report.findings.append(f'Copy-Move forgery detected ({cm_count} correlated keypoint pairs across disparate image regions).')

        combined = (ela_score * 0.5) + (noise_score * 0.3) + (35.0 if cm_detected else 0.0)
        if combined >= 65.0 or cm_detected:
            report.suspicion_level = 'HIGH'
            report.findings.append(f'High tampering probability (Score: {combined:.1f}/100).')
        elif combined >= 35.0:
            report.suspicion_level = 'MEDIUM'
            report.findings.append(f'Moderate compression variance detected (Score: {combined:.1f}/100).')
        else:
            report.suspicion_level = 'LOW'
            if not report.findings:
                report.findings.append('No significant compression or cloning anomalies detected.')
    except Exception as e:
        report.findings.append(f'Tampering analysis error: {str(e)}')

    return report
