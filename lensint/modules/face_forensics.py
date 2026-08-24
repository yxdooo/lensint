import cv2
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def extract_faces_for_analysis(file_path: str) -> Dict[str, Any]:
    """
    Face-ROI Extractor.
    Extracts bounding boxes of faces in the image. Deepfakes (Face Swaps)
    usually only manipulate the face, leaving the background pristine.
    By extracting faces, we can run targeted neural analysis on the ROI.
    """
    img = cv2.imread(file_path)
    if img is None:
        return {"face_extraction_performed": False, "error": "Could not read image."}
        
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    # Load OpenCV's pre-trained Haar Cascade for frontal faces
    # This requires opencv-python package (which we have via cv2)
    try:
        cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        face_cascade = cv2.CascadeClassifier(cascade_path)
        
        if face_cascade.empty():
            return {"face_extraction_performed": False, "error": "Haar cascade XML not found."}
    except AttributeError:
        return {"face_extraction_performed": False, "error": "OpenCV build missing CascadeClassifier."}
        
    faces = face_cascade.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=5,
        minSize=(64, 64) # Ignore tiny faces (too small for reliable deepfake detection)
    )
    
    extracted_rois = []
    for (x, y, w, h) in faces:
        # Expand the bounding box slightly to capture the blending boundaries (forehead, chin, ears)
        pad_x = int(w * 0.2)
        pad_y = int(h * 0.2)
        
        x1 = max(0, x - pad_x)
        y1 = max(0, y - pad_y)
        x2 = min(img.shape[1], x + w + pad_x)
        y2 = min(img.shape[0], y + h + pad_y)
        
        # We don't save the actual pixel array in the JSON result, just metadata
        # The analyzer core will use these coordinates to slice the image and feed to the ONNX model.
        extracted_rois.append({
            "x1": int(x1), "y1": int(y1),
            "x2": int(x2), "y2": int(y2),
            "width": int(x2 - x1),
            "height": int(y2 - y1)
        })
        
    return {
        "face_extraction_performed": True,
        "faces_found": len(extracted_rois),
        "rois": extracted_rois,
        "message": f"Found {len(extracted_rois)} face(s) for targeted Deepfake analysis."
    }
