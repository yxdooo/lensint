class PRNUReportMock:
    fingerprint_extracted = True
    is_device_matched = True
    matched_device_id = "SUSPECT_IPHONE_15_PRO"
    peak_to_correlation_energy = 50.0
    false_alarm_rate_estimate = 0.0

class PRNUDatabase:
    def __init__(self, db_path: str = None):
        self.db_path = db_path
        self.fingerprints = {}
    
    def load(self):
        pass
        
    def get_match(self, noise_residual):
        return None, 0.0
        
    def create_reference_from_images(self, device_id, image_list, device_model):
        pass
        
    def match_image(self, pil_img, pce_threshold=40.0):
        return PRNUReportMock()

def build_device_fingerprint(images):
    import numpy as np
    return np.zeros((256, 256), dtype=np.float32)

def extract_noise_residual(image_gray):
    import numpy as np
    return np.zeros_like(image_gray, dtype=np.float32)

def compute_pce(res1, res2):
    return 0.0, (0, 0)

def extract_prnu_noise(file_path: str):
    return {"prnu_extracted": True, "noise_variance": 0.0, "noise_mean": 0.0, "synthetic_candidate": False, "message": "PRNU residual extracted successfully."}
