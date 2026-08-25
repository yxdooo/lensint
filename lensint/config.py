"""Configuration management module for LENSINT forensics framework.

Supports loading configuration from environment variables, .env files,
and default settings for API keys, cache controls, upload limits, and logging.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


def _load_env_file(env_path: Optional[Path] = None) -> None:
    """Lightweight .env file loader without external dependencies."""
    if env_path is None:
        env_path = Path.cwd() / ".env"
        if not env_path.exists():
            env_path = Path.home() / ".lensint" / ".env"

    if env_path.exists() and env_path.is_file():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip("\"'")
                        if k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass


# Automatically attempt to load .env at module import
_load_env_file()


@dataclass
class LensintConfig:
    # Threat Intelligence API Keys
    virustotal_api_key: Optional[str] = field(default_factory=lambda: os.getenv("LENSINT_VIRUSTOTAL_API_KEY"))
    shodan_api_key: Optional[str] = field(default_factory=lambda: os.getenv("LENSINT_SHODAN_API_KEY"))
    abuseipdb_api_key: Optional[str] = field(default_factory=lambda: os.getenv("LENSINT_ABUSEIPDB_API_KEY"))

    # Server & Upload Limits
    max_upload_size_mb: int = field(default_factory=lambda: int(os.getenv("LENSINT_MAX_UPLOAD_MB", "50")))
    server_host: str = field(default_factory=lambda: os.getenv("LENSINT_HOST", "0.0.0.0"))
    server_port: int = field(default_factory=lambda: int(os.getenv("LENSINT_PORT", "8000")))

    # Cache Configuration
    cache_enabled: bool = field(default_factory=lambda: os.getenv("LENSINT_CACHE_ENABLED", "true").lower() in ("true", "1", "yes"))
    cache_ttl_hours: int = field(default_factory=lambda: int(os.getenv("LENSINT_CACHE_TTL_HOURS", "72")))
    cache_dir: Path = field(default_factory=lambda: Path(os.getenv("LENSINT_CACHE_DIR", str(Path.home() / ".lensint" / "cache"))))

    # Audit Trail & Forensic Logging
    audit_log_enabled: bool = field(default_factory=lambda: os.getenv("LENSINT_AUDIT_ENABLED", "true").lower() in ("true", "1", "yes"))
    audit_log_dir: Path = field(default_factory=lambda: Path(os.getenv("LENSINT_AUDIT_DIR", str(Path.home() / ".lensint" / "audit"))))
    log_level: str = field(default_factory=lambda: os.getenv("LENSINT_LOG_LEVEL", "INFO").upper())

    # ONNX Neural Model Directory
    onnx_model_dir: Optional[str] = field(
        default_factory=lambda: os.getenv("LENSINT_ONNX_MODEL_DIR", "")
    )

    # Geocoding Service
    nominatim_user_agent: str = field(default_factory=lambda: os.getenv("LENSINT_USER_AGENT", "lensint-forensics-agent/2.5"))
    geolookup_timeout_seconds: int = field(default_factory=lambda: int(os.getenv("LENSINT_GEOLOOKUP_TIMEOUT", "3")))

    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    def to_dict(self) -> Dict[str, Any]:
        return {
            "virustotal_configured": bool(self.virustotal_api_key),
            "shodan_configured": bool(self.shodan_api_key),
            "abuseipdb_configured": bool(self.abuseipdb_api_key),
            "max_upload_size_mb": self.max_upload_size_mb,
            "server_host": self.server_host,
            "server_port": self.server_port,
            "cache_enabled": self.cache_enabled,
            "cache_ttl_hours": self.cache_ttl_hours,
            "audit_log_enabled": self.audit_log_enabled,
            "log_level": self.log_level,
        }


# Global configuration instance
config = LensintConfig()
