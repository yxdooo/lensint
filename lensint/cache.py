"""SHA-256 based on-disk result cache for LENSINT analysis results.

Results are stored as JSON in ~/.lensint/cache/<sha256>.json and expire after
CACHE_TTL_HOURS (default 72h). Cache can be disabled per-analysis or globally.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

def _get_cache_dir() -> Path:
    try:
        from lensint.config import config
        return Path(config.cache_dir)
    except Exception:
        return Path.home() / ".lensint" / "cache"


def _get_cache_ttl_seconds() -> int:
    try:
        from lensint.config import config
        return int(config.cache_ttl_hours * 3600)
    except Exception:
        return 72 * 3600


def _cache_path(sha256: str) -> Path:
    return _get_cache_dir() / f"{sha256}.json"


def get_cached(sha256: str) -> Optional[Dict[str, Any]]:
    """Return cached analysis dict if fresh, else None."""
    path = _cache_path(sha256)
    if not path.exists():
        return None
    try:
        mtime = path.stat().st_mtime
        if time.time() - mtime > _get_cache_ttl_seconds():
            path.unlink(missing_ok=True)
            return None
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        path.unlink(missing_ok=True)
        return None


def put_cache(key: str, data: Dict[str, Any]) -> None:
    """Persist analysis result dict to disk cache atomically."""
    import uuid
    try:
        cache_dir = _get_cache_dir()
        cache_dir.mkdir(parents=True, exist_ok=True)
        target_path = _cache_path(key)
        temp_path = target_path.with_suffix(f".{uuid.uuid4().hex}.tmp")
        with temp_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(str(temp_path), str(target_path))
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass
        pass  # cache writes are best-effort


_CACHE_DIR = _get_cache_dir()


def clear_cache() -> int:
    """Remove all cached results. Returns number of files deleted."""
    deleted = 0
    cache_dir = _get_cache_dir()
    if not cache_dir.exists():
        return 0
    for p in cache_dir.glob("*.json"):
        try:
            p.unlink()
            deleted += 1
        except Exception:
            pass
    return deleted


def cache_stats() -> Dict[str, Any]:
    """Return cache stats: count, total_size_bytes, oldest_entry_age_seconds."""
    cache_dir = _get_cache_dir()
    if not cache_dir.exists():
        return {"count": 0, "total_size_bytes": 0, "oldest_entry_age_seconds": 0}
    files = list(cache_dir.glob("*.json"))
    if not files:
        return {"count": 0, "total_size_bytes": 0, "oldest_entry_age_seconds": 0}
    now = time.time()
    sizes = [p.stat().st_size for p in files]
    ages = [now - p.stat().st_mtime for p in files]
    return {
        "count": len(files),
        "total_size_bytes": sum(sizes),
        "oldest_entry_age_seconds": max(ages),
    }
