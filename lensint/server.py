import html
import os
import re
import shutil
import tempfile
from typing import List, Optional
from fastapi import FastAPI, File, UploadFile, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
import uvicorn

from lensint import __version__
from lensint.core.analyzer import ImageAnalyzer
from lensint.reporters.html_rep import render_html_report
from lensint.cache import get_cached, cache_stats, clear_cache

app = FastAPI(
    title='Lensint Image Forensics API',
    description='Automated image forensics, AI detection, and threat intelligence REST API',
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB


def _sanitize_extension(filename: Optional[str]) -> str:
    if not filename:
        return ".bin"
    _, raw_ext = os.path.splitext(filename)
    clean_ext = re.sub(r"[^a-zA-Z0-9.]", "", raw_ext.lower())
    return clean_ext if clean_ext else ".bin"


def _process_upload(file: UploadFile, ela_quality: int, geo_lookup: bool,
                    generate_visuals: bool, use_cache: bool):
    ext = _sanitize_extension(file.filename)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    tmp_path = tmp.name
    try:
        tmp.close()
        with open(tmp_path, "wb") as f_dst:
            shutil.copyfileobj(file.file, f_dst)

        if os.path.getsize(tmp_path) > MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(status_code=413, detail=f"File exceeds maximum allowed upload size ({MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB).")

        analyzer = ImageAnalyzer(
            tmp_path,
            ela_quality=ela_quality,
            perform_geolookup=geo_lookup,
            generate_visuals=generate_visuals,
            use_cache=use_cache,
        )
        return analyzer.analyze()
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


@app.get('/health')
def healthcheck():
    return {'status': 'healthy', 'service': 'lensint-api', 'version': __version__}


@app.get("/")
async def serve_ui():
    """Serve the drag-and-drop Web UI."""
    ui_path = os.path.join(os.path.dirname(__file__), "web", "index.html")
    if os.path.exists(ui_path):
        return FileResponse(ui_path)
    return HTMLResponse("<h3>LENSINT Web UI is available.</h3>")


@app.post('/api/analyze')
async def analyze_image_json(
    file: UploadFile = File(...),
    ela_quality: int = Query(90, ge=1, le=100),
    geo_lookup: bool = Query(False),
    generate_visuals: bool = Query(False, description="Include base64-encoded visual images in the response"),
    use_cache: bool = Query(True),
):
    try:
        result = _process_upload(file, ela_quality, geo_lookup, generate_visuals, use_cache)
        return JSONResponse(content=result.to_dict())
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Analysis failed", "details": str(e)})


@app.post('/api/analyze/html', response_class=HTMLResponse)
async def analyze_image_html(
    file: UploadFile = File(...),
    ela_quality: int = Query(90, ge=1, le=100),
    geo_lookup: bool = Query(True),
    generate_visuals: bool = Query(True, description="Include base64-encoded visual images in the HTML report"),
    use_cache: bool = Query(True),
):
    try:
        result = _process_upload(file, ela_quality, geo_lookup, generate_visuals, use_cache)
        return HTMLResponse(content=render_html_report(result))
    except HTTPException:
        raise
    except Exception as e:
        return HTMLResponse(f"<h3>Forensics Analysis Error</h3><p>{html.escape(str(e))}</p>", status_code=500)


@app.post("/api/analyze/batch")
async def analyze_batch(
    files: List[UploadFile] = File(...),
    ela_quality: int = Query(90, ge=1, le=100),
    geo_lookup: bool = Query(False),
    generate_visuals: bool = Query(False),
    use_cache: bool = Query(True),
):
    """Analyze multiple images in one request. Returns list of results."""
    results = []
    for file in files:
        try:
            result = _process_upload(file, ela_quality, geo_lookup, generate_visuals, use_cache)
            results.append(result.to_dict())
        except Exception as e:
            results.append({"error": str(e), "filename": file.filename})
    return JSONResponse(content={"results": results, "count": len(results)})


@app.get("/api/cache/stats")
async def get_cache_stats():
    return JSONResponse(content=cache_stats())


@app.delete("/api/cache")
async def clear_cache_endpoint():
    deleted = clear_cache()
    return JSONResponse(content={"deleted": deleted, "message": f"Cleared {deleted} cached results."})


def start_server(host: str = '0.0.0.0', port: int = 8000):
    uvicorn.run(app, host=host, port=port)
