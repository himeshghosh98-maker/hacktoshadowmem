"""
core
====
Core application services, configuration management, and infrastructure for ShadowMem.
"""

from core.config import settings, Settings
from core.logging import setup_logging, get_logger, logger

__all__ = [
    "settings",
    "Settings",
    "setup_logging",
    "get_logger",
    "logger",
]
