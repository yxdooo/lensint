"""High-Performance, Hardened FastAPI REST API & Web UI Server for LENSINT."""
from __future__ import annotations

import html
import os
import re
import tempfile
from typing import List, Optional
from fastapi import FastAPI, File, Header, HTTPException, Query, Security, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

from lensint import __version__
from lensint.config import config
from lensint.core.analyzer import ImageAnalyzer
from lensint.reporters.html_rep import render_html_report
from lensint.cache import get_cached, cache_stats, clear_cache

app = FastAPI(
    title="Lensint Image Forensics API",
    description="Automated digital image forensics, AI detection, and threat intelligence REST API",
    version=__version__,
)

# Hardened CORS configuration
cors_env = os.getenv("LENSINT_CORS_ORIGINS", "").strip()
if cors_env == "*":
    allowed_origins = ["*"]
elif cors_env:
    allowed_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
else:
    allowed_origins = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Mount Static Assets
static_dir = os.path.join(os.path.dirname(__file__), "web", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

MAX_UPLOAD_SIZE_BYTES = config.max_upload_size_bytes
API_KEY_ENV = os.getenv("LENSINT_API_KEY", "").strip()


def _verify_api_key(x_api_key: Optional[str] = Header(None), authorization: Optional[str] = Header(None)) -> None:
    """Validate API key if LENSINT_API_KEY environment variable is configured."""
    if not API_KEY_ENV:
        return  # Open mode when no secret key configured
    
    token = x_api_key
    if not token and authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        
    if not token or token != API_KEY_ENV:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing LENSINT API Key.")


def _sanitize_extension(filename: Optional[str]) -> str:
    if not filename:
        return ".bin"
    _, raw_ext = os.path.splitext(filename)
    clean_ext = re.sub(r"[^a-zA-Z0-9.]", "", raw_ext.lower())
    return clean_ext if clean_ext else ".bin"


def _process_upload_streaming(
    file: UploadFile,
    ela_quality: int,
    geo_lookup: bool,
    generate_visuals: bool,
    use_cache: bool,
):
    """Stream file upload with strict byte-limit enforcement to prevent disk exhaustion."""
    ext = _sanitize_extension(file.filename)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    tmp_path = tmp.name
    total_bytes = 0
    chunk_size = 64 * 1024  # 64 KB streaming buffer

    try:
        tmp.close()
        with open(tmp_path, "wb") as f_dst:
            while True:
                chunk = file.file.read(chunk_size)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeded maximum allowed size ({config.max_upload_size_mb} MB).",
                    )
                f_dst.write(chunk)

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


@app.get("/health")
def healthcheck():
    return {
        "status": "healthy",
        "service": "lensint-api",
        "version": __version__,
        "auth_enabled": bool(API_KEY_ENV),
        "cors_origins": allowed_origins,
        "config": config.to_dict(),
    }


@app.get("/")
async def serve_ui():
    """Serve the drag-and-drop Web UI."""
    template_path = os.path.join(os.path.dirname(__file__), "web", "templates", "index.html")
    if os.path.exists(template_path):
        return FileResponse(template_path)
    legacy_path = os.path.join(os.path.dirname(__file__), "web", "index.html")
    if os.path.exists(legacy_path):
        return FileResponse(legacy_path)
    return HTMLResponse("<h3>LENSINT Web UI is available.</h3>")


from starlette.concurrency import run_in_threadpool


@app.post("/api/analyze")
async def analyze_image_json(
    file: UploadFile = File(...),
    ela_quality: int = Query(90, ge=1, le=100),
    geo_lookup: bool = Query(False),
    generate_visuals: bool = Query(False, description="Include base64-encoded visual images in the response"),
    use_cache: bool = Query(True),
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _verify_api_key(x_api_key, authorization)
    try:
        result = await run_in_threadpool(
            _process_upload_streaming, file, ela_quality, geo_lookup, generate_visuals, use_cache
        )
        return JSONResponse(content=result.to_dict())
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Analysis failed", "details": str(e)})


@app.post("/api/analyze/html", response_class=HTMLResponse)
async def analyze_image_html(
    file: UploadFile = File(...),
    ela_quality: int = Query(90, ge=1, le=100),
    geo_lookup: bool = Query(True),
    generate_visuals: bool = Query(True, description="Include base64-encoded visual images in the HTML report"),
    use_cache: bool = Query(True),
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _verify_api_key(x_api_key, authorization)
    try:
        result = await run_in_threadpool(
            _process_upload_streaming, file, ela_quality, geo_lookup, generate_visuals, use_cache
        )
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
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    """Analyze multiple images in one request with streaming safety."""
    _verify_api_key(x_api_key, authorization)
    results = []
    for file in files:
        try:
            result = await run_in_threadpool(
                _process_upload_streaming, file, ela_quality, geo_lookup, generate_visuals, use_cache
            )
            results.append(result.to_dict())
        except Exception as e:
            results.append({"error": str(e), "filename": file.filename})
    return JSONResponse(content={"results": results, "count": len(results)})


@app.get("/api/cache/stats")
async def get_cache_stats():
    return JSONResponse(content=cache_stats())


@app.delete("/api/cache")
async def clear_cache_endpoint(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _verify_api_key(x_api_key, authorization)
    deleted = clear_cache()
    return JSONResponse(content={"deleted": deleted, "message": f"Cleared {deleted} cached results."})


def start_server(host: str = "127.0.0.1", port: int = 8000):
    uvicorn.run(app, host=host, port=port)
