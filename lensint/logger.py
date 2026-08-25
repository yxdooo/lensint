"""Centralized logging module for LENSINT framework.
"""
from __future__ import annotations

import logging
import sys
from lensint.config import config


def setup_logger(name: str = "lensint") -> logging.Logger:
    """Configures and returns a standardized logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        level_str = config.log_level
        log_level = getattr(logging, level_str, logging.INFO)
        logger.setLevel(log_level)

        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(log_level)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
