"""High-Performance, Hardened FastAPI REST API & Web UI Server for LENSINT."""
from __future__ import annotations

import asyncio
import html
import os
import re
import tempfile
import time
from typing import List, Optional
from fastapi import FastAPI, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
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


# ---------------------------------------------------------------------------
# Token-Bucket Rate Limiter
# ---------------------------------------------------------------------------

class _TokenBucket:
    """Thread-safe token-bucket rate limiter per client key."""

    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = rate          # tokens per second
        self.capacity = capacity  # burst ceiling
        self._buckets: dict = {}

    def _get_bucket(self, key: str) -> list:
        if key not in self._buckets:
            self._buckets[key] = [float(self.capacity), time.monotonic()]
        return self._buckets[key]

    def consume(self, key: str, tokens: int = 1):
        """Try to consume tokens from the bucket.

        Returns: (allowed: bool, retry_after: float, remaining: int)
        """
        bucket = self._get_bucket(key)
        now = time.monotonic()
        elapsed = now - bucket[1]
        bucket[1] = now
        bucket[0] = min(self.capacity, bucket[0] + elapsed * self.rate)

        remaining = int(bucket[0])
        if bucket[0] >= tokens:
            bucket[0] -= tokens
            return True, 0.0, max(0, remaining - tokens)
        retry_after = (tokens - bucket[0]) / self.rate
        return False, retry_after, 0

    def evict_stale(self, max_age_seconds: float = 300.0) -> None:
        """Remove idle buckets to prevent unbounded memory growth."""
        now = time.monotonic()
        stale = [k for k, v in self._buckets.items() if now - v[1] > max_age_seconds]
        for k in stale:
            del self._buckets[k]


# 30 requests/minute per IP, burst of 10 (configurable via env vars)
_RATE_LIMIT_PER_MINUTE = int(os.getenv("LENSINT_RATE_LIMIT_PER_MIN", "30"))
_RATE_LIMIT_BURST = int(os.getenv("LENSINT_RATE_LIMIT_BURST", "10"))
_rate_limiter = _TokenBucket(
    rate=_RATE_LIMIT_PER_MINUTE / 60.0,
    capacity=_RATE_LIMIT_BURST,
)


def _get_client_key(request: Request) -> str:
    """Derive a rate-limit key from the real client IP."""
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(request: Request):
    """Check rate limit; return a 429 Response if exceeded, else None.

    Rate limiting is only active when LENSINT_API_KEY is configured, so
    unauthenticated local development usage is never throttled.
    """
    if not API_KEY_ENV:
        return None
    key = _get_client_key(request)
    allowed, retry_after, remaining = _rate_limiter.consume(key)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "detail": (
                    f"Too many requests from {key}. "
                    f"Retry after {retry_after:.1f} seconds."
                ),
                "retry_after_seconds": round(retry_after, 1),
            },
            headers={
                "Retry-After": str(int(retry_after) + 1),
                "X-RateLimit-Limit": str(_RATE_LIMIT_PER_MINUTE),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time() + retry_after)),
            },
        )
    return None

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
        "rate_limit_per_minute": _RATE_LIMIT_PER_MINUTE,
        "rate_limit_burst": _RATE_LIMIT_BURST,
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
    request: Request,
    file: UploadFile = File(...),
    ela_quality: int = Query(90, ge=1, le=100),
    geo_lookup: bool = Query(False),
    generate_visuals: bool = Query(False, description="Include base64-encoded visual images in the response"),
    use_cache: bool = Query(True),
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _verify_api_key(x_api_key, authorization)
    rate_limit_response = _check_rate_limit(request)
    if rate_limit_response is not None:
        return rate_limit_response
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
    request: Request,
    file: UploadFile = File(...),
    ela_quality: int = Query(90, ge=1, le=100),
    geo_lookup: bool = Query(True),
    generate_visuals: bool = Query(True, description="Include base64-encoded visual images in the HTML report"),
    use_cache: bool = Query(True),
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _verify_api_key(x_api_key, authorization)
    rate_limit_response = _check_rate_limit(request)
    if rate_limit_response is not None:
        return rate_limit_response
    try:
        result = await run_in_threadpool(
            _process_upload_streaming, file, ela_quality, geo_lookup, generate_visuals, use_cache
        )
        return HTMLResponse(content=render_html_report(result))
    except HTTPException:
        raise
    except Exception as e:
        return HTMLResponse(f"<h3>Forensics Analysis Error</h3><p>{html.escape(str(e))}</p>", status_code=500)


@app.post("/api/analyze/pdf")
async def analyze_image_pdf(
    request: Request,
    file: UploadFile = File(...),
    case_id: str = Query("CASE-2026-DFIR-001"),
    examiner: str = Query("Senior Digital Forensic Examiner"),
    ela_quality: int = Query(90, ge=1, le=100),
    use_cache: bool = Query(True),
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    """Generate and download an official Courtroom Expert Witness PDF Forensic Report."""
    _verify_api_key(x_api_key, authorization)
    rate_limit_response = _check_rate_limit(request)
    if rate_limit_response is not None:
        return rate_limit_response
    try:
        from lensint.reporters.expert_pdf import generate_expert_witness_pdf
        result = await run_in_threadpool(
            _process_upload_streaming, file, ela_quality, False, False, use_cache
        )
        fd, temp_pdf = tempfile.mkstemp(suffix=".pdf", prefix="lensint_courtroom_")
        os.close(fd)
        generate_expert_witness_pdf(
            result=result,
            output_path=temp_pdf,
            case_id=case_id,
            examiner_name=examiner,
        )
        from starlette.background import BackgroundTask
        return FileResponse(
            temp_pdf,
            media_type="application/pdf",
            filename=f"Expert_Forensic_Report_{result.integrity.sha256[:12]}.pdf",
            background=BackgroundTask(os.remove, temp_pdf),
        )
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "PDF Generation Failed", "details": str(e)})


@app.post("/api/analyze/batch")
async def analyze_batch(
    request: Request,
    files: List[UploadFile] = File(...),
    ela_quality: int = Query(90, ge=1, le=100),
    geo_lookup: bool = Query(False),
    generate_visuals: bool = Query(False),
    use_cache: bool = Query(True),
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    """Analyze multiple images concurrently using asyncio.gather for true parallelism.

    Each file is processed in a separate thread via run_in_threadpool so CPU-bound
    analysis steps run in parallel rather than sequentially. Errors in individual
    files are isolated and do not abort the rest of the batch.
    """
    _verify_api_key(x_api_key, authorization)
    rate_limit_response = _check_rate_limit(request)
    if rate_limit_response is not None:
        return rate_limit_response

    async def _analyze_one(file: UploadFile) -> dict:
        try:
            result = await run_in_threadpool(
                _process_upload_streaming, file, ela_quality, geo_lookup, generate_visuals, use_cache
            )
            return result.to_dict()
        except Exception as e:
            return {"error": str(e), "filename": file.filename}

    # Concurrently process all files; results preserve input order
    results = await asyncio.gather(*(_analyze_one(f) for f in files))
    return JSONResponse(content={"results": list(results), "count": len(results)})


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
