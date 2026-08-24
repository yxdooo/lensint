import numpy as np
import cv2
import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

def detect_double_quantization(file_path: str) -> Dict[str, Any]:
    """
    Detects JPEG Double Quantization (DQ) artifacts.
    When a JPEG is resaved at a different quality (often due to editing),
    the DCT coefficients exhibit periodic artifacts.
    """
    # Verify if it's a JPEG
    with open(file_path, 'rb') as f:
        header = f.read(2)
        if header != b'\xff\xd8':
            return {"dq_detected": False, "message": "Not a JPEG file, skipping DQ analysis."}

    # Reading DCT coefficients directly requires libjpeg hooks, which is complex in pure Python.
    # As an alternative, we approximate the DQ probability using histogram analysis 
    # of the first AC coefficients in 8x8 blocks, which is a known spatial domain approximation.
    
    img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return {"dq_detected": False, "error": "Could not read image for DQ analysis."}

    # Extract 8x8 blocks
    h, w = img.shape
    h = h - (h % 8)
    w = w - (w % 8)
    img = img[:h, :w]
    
    # Calculate 2D DCT for each 8x8 block
    blocks = np.zeros((h // 8, w // 8, 8, 8))
    for i in range(0, h, 8):
        for j in range(0, w, 8):
            block = img[i:i+8, j:j+8].astype(np.float32)
            block -= 128.0
            dct = cv2.dct(block)
            blocks[i//8, j//8] = dct

    # Analyze the histogram of the (1,1) AC coefficient
    ac11 = blocks[:, :, 1, 1].flatten()
    hist, bins = np.histogram(ac11, bins=100, range=(-50, 50))
    
    # Check for periodicity (peaks and valleys) in the histogram using Fourier Transform
    hist_fft = np.abs(np.fft.fft(hist - np.mean(hist)))
    # Ignore the DC and very low frequency components
    hist_fft[:3] = 0
    peak_ratio = np.max(hist_fft) / (np.mean(hist_fft) + 1e-5)
    
    # A high peak in the Fourier transform of the histogram suggests periodic gaps (DQ)
    dq_threshold = 4.0
    is_dq = peak_ratio > dq_threshold
    
    return {
        "dq_detected": bool(is_dq),
        "peak_ratio": float(peak_ratio),
        "message": "Double quantization artifacts detected (indicates re-saving)" if is_dq else "No strong double quantization artifacts detected"
    }

def analyze_ghosting(file_path: str) -> Dict[str, Any]:
    """
    Implements a basic JPEG Ghost detection.
    Re-compresses the image at multiple qualities and looks for localized differences.
    Areas that stand out significantly at a specific quality level might be forged.
    """
    img = cv2.imread(file_path)
    if img is None:
        return {"ghost_detected": False}

    h, w, _ = img.shape
    if h * w > 4000000:
        # Resize to speed up analysis if > 4 Megapixels
        scale = 2000 / max(h, w)
        img = cv2.resize(img, (int(w*scale), int(h*scale)))

    qualities = [65, 75, 85, 95]
    ghost_scores = []
    
    for q in qualities:
        # Re-compress
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), q]
        result, encimg = cv2.imencode('.jpg', img, encode_param)
        decimg = cv2.imdecode(encimg, 1)
        
        # Calculate squared difference
        diff = cv2.absdiff(img, decimg)
        diff_sq = np.square(diff.astype(np.float32))
        
        # Smooth and find local anomalies
        smoothed = cv2.GaussianBlur(np.mean(diff_sq, axis=2), (15, 15), 0)
        global_mean = np.mean(smoothed)
        local_max = np.max(smoothed)
        
        if global_mean > 0:
            ratio = local_max / global_mean
            ghost_scores.append(ratio)
        else:
            ghost_scores.append(1.0)
            
    max_ghost_score = max(ghost_scores)
    is_ghost = max_ghost_score > 15.0  # Empirical threshold

    return {
        "ghost_detected": bool(is_ghost),
        "max_anomaly_ratio": float(max_ghost_score),
        "message": "Localized JPEG ghost anomalies detected" if is_ghost else "No localized ghosts detected"
    }
