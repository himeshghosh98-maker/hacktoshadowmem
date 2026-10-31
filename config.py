"""
config.py
=========
Root configuration re-export for ShadowMem.
Delegates to core.config.settings.
"""

from core.config import settings, Settings

__all__ = ["settings", "Settings"]
