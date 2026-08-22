import os
import shutil
import tempfile
from fastapi import FastAPI, File, UploadFile, Query
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

from lensint import __version__
from lensint.core.analyzer import ImageAnalyzer
from lensint.reporters.html_rep import render_html_report

app = FastAPI(
    title='Lensint Image Forensics API',
    description='Automated image forensics, AI detection, and threat intelligence REST API',
    version=__version__,
)


@app.get('/health')
def healthcheck():
    return {'status': 'healthy', 'service': 'lensint-api', 'version': __version__}


@app.post('/api/analyze')
async def analyze_image_json(
    file: UploadFile = File(...),
    ela_quality: int = Query(90, ge=1, le=100),
    geo_lookup: bool = Query(False),
):
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[-1]) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        analyzer = ImageAnalyzer(tmp_path, ela_quality=ela_quality, perform_geolookup=geo_lookup)
        result = analyzer.analyze()
        return JSONResponse(content=result.to_dict())
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.post('/api/analyze/html', response_class=HTMLResponse)
async def analyze_image_html(
    file: UploadFile = File(...),
    ela_quality: int = Query(90, ge=1, le=100),
    geo_lookup: bool = Query(True),
):
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[-1]) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        analyzer = ImageAnalyzer(tmp_path, ela_quality=ela_quality, perform_geolookup=geo_lookup)
        result = analyzer.analyze()
        return HTMLResponse(content=render_html_report(result))
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def start_server(host: str = '0.0.0.0', port: int = 8000):
    uvicorn.run(app, host=host, port=port)
