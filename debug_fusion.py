import os
from PIL import Image
from lensint.core.analyzer import ImageAnalyzer
img = Image.new("RGB", (1920, 1080), color=(240, 240, 240))
p = "debug_screenshot.png"
img.save(p, format="PNG")
res = ImageAnalyzer(p).analyze()
print("Risk Level:", res.overall_risk_level)
