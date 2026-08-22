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

CACHE_TTL_SECONDS: int = 72 * 3600  # 72 hours
_CACHE_DIR: Path = Path.home() / ".lensint" / "cache"


def _cache_path(sha256: str) -> Path:
    return _CACHE_DIR / f"{sha256}.json"


def get_cached(sha256: str) -> Optional[Dict[str, Any]]:
    """Return cached analysis dict if fresh, else None."""
    path = _cache_path(sha256)
    if not path.exists():
        return None
    try:
        mtime = path.stat().st_mtime
        if time.time() - mtime > CACHE_TTL_SECONDS:
            path.unlink(missing_ok=True)
            return None
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def put_cache(sha256: str, data: Dict[str, Any]) -> None:
    """Persist analysis result dict to disk cache."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with _cache_path(sha256).open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        pass  # cache writes are best-effort


def clear_cache() -> int:
    """Remove all cached results. Returns number of files deleted."""
    deleted = 0
    if not _CACHE_DIR.exists():
        return 0
    for p in _CACHE_DIR.glob("*.json"):
        try:
            p.unlink()
            deleted += 1
        except Exception:
            pass
    return deleted


def cache_stats() -> Dict[str, Any]:
    """Return cache stats: count, total_size_bytes, oldest_entry_age_seconds."""
    if not _CACHE_DIR.exists():
        return {"count": 0, "total_size_bytes": 0, "oldest_entry_age_seconds": 0}
    files = list(_CACHE_DIR.glob("*.json"))
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
