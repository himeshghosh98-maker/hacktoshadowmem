"""
core/logging.py
===============
Structured logging configuration for ShadowMem.
Ensures uniform timestamped formatting and avoids duplicate handlers.
"""

import logging
import sys
from typing import Optional
from core.config import settings


def setup_logging(
    log_level: Optional[str] = None,
    log_format: Optional[str] = None,
) -> logging.Logger:
    """Configure and return the root ShadowMem logger."""
    level_name = (log_level or settings.log_level).upper()
    level = getattr(logging, level_name, logging.INFO)
    fmt = log_format or settings.log_format

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Avoid adding duplicate handlers if already configured
    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = logging.Formatter(fmt)
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)
    else:
        for handler in root_logger.handlers:
            handler.setLevel(level)
            handler.setFormatter(logging.Formatter(fmt))

    app_logger = logging.getLogger("shadowmem")
    app_logger.setLevel(level)
    return app_logger


def get_logger(name: str = "shadowmem") -> logging.Logger:
    """Retrieve a named child logger."""
    return logging.getLogger(name)


# Initialize default logger
logger = setup_logging()
