"""
LENSINT - Image Forensics, AI Detection & Threat Intelligence Framework
"""

__version__ = "3.5.0"
__author__ = "Lensint Security Team"

from lensint.core.analyzer import ImageAnalyzer
from lensint.core.models import AnalysisResult

__all__ = ["ImageAnalyzer", "AnalysisResult", "__version__"]
