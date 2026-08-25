import cv2
import numpy as np
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

def analyze_video_temporal_consistency(video_path: str, max_frames: int = 150) -> Dict[str, Any]:
    """
    Analyzes temporal consistency in a video to detect deepfake flickering.
    Generative AI models often struggle to maintain frame-to-frame pixel consistency,
    resulting in micro-flickers (high frequency temporal noise).
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return {"temporal_analysis_completed": False, "error": "Could not open video file."}
        
    frame_count = 0
    prev_frame = None
    diff_scores = []
    
    while cap.isOpened() and frame_count < max_frames:
        ret, frame = cap.read()
        if not ret:
            break
            
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        
        if prev_frame is not None:
            # Absolute difference between consecutive frames
            diff = cv2.absdiff(gray, prev_frame)
            mean_diff = np.mean(diff)
            diff_scores.append(mean_diff)
            
        prev_frame = gray
        frame_count += 1
        
    cap.release()
    
    if not diff_scores:
        return {"temporal_analysis_completed": False, "error": "Not enough frames to analyze."}
        
    # Analyze the diff scores for unnatural spikes (flickering)
    diff_array = np.array(diff_scores)
    
    # Calculate the temporal volatility (standard deviation of the differences)
    # Natural video has smooth motion (low variance in diffs over a short window).
    # Deepfakes often have sudden spikes.
    volatility = np.std(diff_array)
    max_diff = np.max(diff_array)
    mean_diff = np.mean(diff_array)
    
    # A high spike relative to the mean indicates a sudden glitch/flicker
    spike_ratio = max_diff / (mean_diff + 1e-5)
    
    is_flickering = spike_ratio > 5.0 or volatility > 15.0
    
    return {
        "temporal_analysis_completed": True,
        "frames_analyzed": frame_count,
        "temporal_volatility": float(volatility),
        "spike_ratio": float(spike_ratio),
        "flickering_detected": bool(is_flickering),
        "message": "AI-generated temporal flickering detected" if is_flickering else "Temporal frame progression appears natural"
    }
