import os
import subprocess
import tempfile
import logging
import numpy as np
from typing import Dict, Any
import scipy.io.wavfile as wavfile
import scipy.signal as signal

logger = logging.getLogger(__name__)

def analyze_audio_deepfake(media_path: str) -> Dict[str, Any]:
    """
    Extracts audio using FFmpeg and performs basic Spectral analysis
    to detect Voice Cloning / AI Audio generation (e.g. ElevenLabs, VITS).
    AI audio often exhibits unnatural high-frequency roll-offs or phase anomalies.
    """
    if not os.path.exists(media_path):
        return {"audio_analysis_performed": False, "error": "Media file not found."}
        
    result = {
        "audio_analysis_performed": False,
        "is_synthetic_audio": False,
        "spectral_anomaly_score": 0.0,
        "message": "Audio deepfake analysis failed."
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        wav_path = os.path.join(tmpdir, "extracted.wav")
        # Extract mono, 16kHz WAV using FFmpeg
        cmd = [
            "ffmpeg", "-y", "-i", media_path, 
            "-vn", "-acodec", "pcm_s16le", 
            "-ar", "16000", "-ac", "1", 
            wav_path
        ]
        
        try:
            # Hide output, timeout after 30 seconds
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        except Exception as e:
            result["error"] = f"FFmpeg extraction failed: {str(e)}"
            return result
            
        if not os.path.exists(wav_path):
            result["error"] = "No audio track found in media."
            return result
            
        try:
            # Read WAV
            sample_rate, data = wavfile.read(wav_path)
            if len(data) < sample_rate: # Less than 1 second of audio
                result["error"] = "Audio track too short for analysis."
                return result
                
            # Compute Spectrogram
            # f: frequencies, t: times, Sxx: spectrogram array
            f, t, Sxx = signal.spectrogram(data, fs=sample_rate, nperseg=512, noverlap=256)
            
            # AI voice clones often struggle with high frequencies (> 5kHz) 
            # They tend to have a much sharper, unnatural cutoff compared to human microphones.
            # We calculate the energy ratio between low bands and high bands.
            high_freq_idx = np.where(f > 5000)[0]
            low_freq_idx = np.where(f <= 5000)[0]
            
            if len(high_freq_idx) == 0 or len(low_freq_idx) == 0:
                result["error"] = "Invalid frequency bins."
                return result
                
            high_energy = np.mean(Sxx[high_freq_idx, :])
            low_energy = np.mean(Sxx[low_freq_idx, :])
            
            energy_ratio = low_energy / (high_energy + 1e-10)
            
            # Extreme energy ratio implies a synthetic low-pass filter or vocoder artifacts
            # Typical human speech ratio varies, but AI often exceeds extreme thresholds
            # We also look at the variance across time to detect robot-like monotonic delivery
            time_variance = np.var(np.mean(Sxx, axis=0))
            
            score = 0.0
            if energy_ratio > 5000.0:
                score += 0.5
            if time_variance < 0.1: # Extremely monotonic
                score += 0.5
                
            result["audio_analysis_performed"] = True
            result["spectral_anomaly_score"] = float(score)
            result["is_synthetic_audio"] = score >= 0.5
            
            if result["is_synthetic_audio"]:
                result["message"] = f"AI Voice Cloning Detected! (Unnatural spectral energy ratio: {energy_ratio:.1f})"
            else:
                result["message"] = "Audio spectrum appears natural."
                
        except Exception as e:
            result["error"] = f"Audio processing failed: {str(e)}"
            
    return result
