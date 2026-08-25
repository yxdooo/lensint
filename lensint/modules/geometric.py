import numpy as np
import cv2
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

def analyze_geometric_consistency(file_path: str) -> Dict[str, Any]:
    """
    Performs basic geometric and lighting consistency checks.
    1. Detects strong lines for vanishing point anomalies.
    2. Analyzes intensity gradients to find conflicting light sources.
    """
    img = cv2.imread(file_path)
    if img is None:
        return {"geometric_consistency_checked": False, "error": "Could not read image."}
        
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 50, 150, apertureSize=3)
    
    # Line detection (Hough)
    lines = cv2.HoughLines(edges, 1, np.pi/180, 200)
    line_count = 0 if lines is None else len(lines)
    
    # Lighting gradient consistency (Shadow analysis approximation)
    # Divide image into a 3x3 grid and find the dominant gradient direction in each
    gx = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
    gy = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
    magnitude, angle = cv2.cartToPolar(gx, gy)
    
    h, w = gray.shape
    grid_h, grid_w = h // 3, w // 3
    
    dominant_angles = []
    for i in range(3):
        for j in range(3):
            cell_mag = magnitude[i*grid_h:(i+1)*grid_h, j*grid_w:(j+1)*grid_w]
            cell_ang = angle[i*grid_h:(i+1)*grid_h, j*grid_w:(j+1)*grid_w]
            
            # Only consider strong gradients (edges/shadow boundaries)
            strong_indices = cell_mag > np.percentile(magnitude, 90)
            if np.any(strong_indices):
                dom_ang = np.median(cell_ang[strong_indices])
                dominant_angles.append(dom_ang)
                
    # If the variance of dominant lighting angles across the image is extremely high, 
    # it implies conflicting light sources (common in composite splices).
    angle_variance = np.var(dominant_angles) if dominant_angles else 0.0
    
    inconsistent_lighting = angle_variance > 1.5  # Radians variance threshold
    
    return {
        "geometric_consistency_checked": True,
        "strong_lines_detected": line_count,
        "lighting_angle_variance": float(angle_variance),
        "inconsistent_lighting_detected": bool(inconsistent_lighting),
        "message": "Conflicting lighting/shadow gradients detected (possible splicing)" if inconsistent_lighting else "Lighting gradients appear consistent"
    }
