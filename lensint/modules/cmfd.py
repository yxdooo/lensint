import cv2
import numpy as np
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

def analyze_cmfd(file_path: str) -> Dict[str, Any]:
    """
    Copy-Move Forgery Detection (CMFD) using ORB keypoints.
    Detects if a region of the image was copied and pasted elsewhere (e.g. Photoshop Clone Stamp).
    """
    img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return {"cmfd_performed": False, "error": "Could not read image for CMFD."}
        
    # Resize if too large to prevent out-of-memory or extreme slow-downs
    h, w = img.shape
    max_dim = 1500
    if max(h, w) > max_dim:
        scale = max_dim / max(h, w)
        img = cv2.resize(img, (int(w*scale), int(h*scale)))

    # Initialize ORB detector
    orb = cv2.ORB_create(nfeatures=2000)
    keypoints, descriptors = orb.detectAndCompute(img, None)
    
    if descriptors is None or len(descriptors) < 50:
        return {"cmfd_performed": True, "cloned_regions_detected": False, "message": "Not enough keypoints."}

    # Brute Force Matcher
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
    # Get 2-nearest neighbors to apply Lowe's ratio test (modified for self-similarity)
    matches = bf.knnMatch(descriptors, descriptors, k=3)
    
    good_matches = []
    # In self-matching, the first match (k=1) is the point itself (distance=0).
    # We look at the second match (k=2). If it's very close (low distance), it's a clone.
    for match_set in matches:
        if len(match_set) >= 2:
            m1 = match_set[0] # Self
            m2 = match_set[1] # Potential clone
            
            # Avoid matching spatially adjacent pixels (natural textures)
            pt1 = np.array(keypoints[m1.queryIdx].pt)
            pt2 = np.array(keypoints[m2.trainIdx].pt)
            spatial_dist = np.linalg.norm(pt1 - pt2)
            
            if m2.distance < 45 and spatial_dist > 50:
                good_matches.append(m2)

    # To be confident it's a clone brush and not just identical windows on a building,
    # we need a high concentration of cloned points.
    min_match_count = 15
    is_cloned = len(good_matches) > min_match_count
    
    return {
        "cmfd_performed": True,
        "cloned_regions_detected": bool(is_cloned),
        "suspicious_match_count": len(good_matches),
        "message": f"Copy-Move Forgery Detected! ({len(good_matches)} cloned keypoints)" if is_cloned else "No significant clone regions detected."
    }
