"""
core/config.py
==============
Centralized configuration & settings management for ShadowMem.

Settings are resolved, in priority order, from:
  1. Explicit keyword arguments (``Settings(port=...)``)
  2. ``SHADOWMEM_``-prefixed environment variables (e.g. ``SHADOWMEM_PORT``)
  3. The ``.env`` file next to the repository root (``SHADOWMEM_``-prefixed keys)
  4. Field defaults declared below

Validation and coercion are delegated to ``pydantic-settings``; collection
fields additionally accept comma-separated or JSON-array strings, and
``log_level`` is normalized to upper case.
"""

import json
from pathlib import Path
from typing import Annotated, Any, List, Set, Tuple

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _parse_list_or_set(val: Any) -> List[str]:
    """Parse comma-separated string or list into a list of strings."""
    if val is None:
        return []
    if isinstance(val, (list, set, tuple)):
        return [str(x).strip() for x in val]
    if isinstance(val, str):
        val = val.strip()
        if val.startswith("[") and val.endswith("]"):
            try:
                parsed = json.loads(val)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed]
            except Exception:
                pass
        return [item.strip() for item in val.split(",") if item.strip()]
    return [str(val)]


# Default sets for forensic safety and detection
DEFAULT_JIT_ENGINE_ALLOWLIST = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "code.exe",
    "discord.exe",
    "antigravity.exe",
    "slack.exe",
    "teams.exe",
    "electron.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
}

DEFAULT_MANAGED_RUNTIME_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "dotnet.exe",
}

DEFAULT_CRITICAL_SYSTEM_PROCESSES = {
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "smss.exe",
    "explorer.exe",
    "system",
    "idle",
    "registry",
    "dwm.exe",
    "fontdrvhost.exe",
}


class Settings(BaseSettings):
    """Application and engine configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix='SHADOWMEM_',
        env_file='.env',
        extra='ignore',
    )

    # ---- Server & Application ----
    app_title: str = Field("ShadowMem", description="FastAPI application title")
    app_description: str = Field(
        "Automated volatile memory forensics and fileless malware detection.",
        description="Application description in OpenAPI docs"
    )
    app_version: str = Field("1.0.0", description="API version")
    host: str = Field("0.0.0.0", description="Bind host address")
    port: int = Field(8000, description="Bind port")
    reload: bool = Field(False, description="Enable auto-reload for development")
    api_prefix: str = Field("/api/v1", description="Prefix for versioned API endpoints")
    cors_origins: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8000",
        ],
        description="Allowed CORS origins",
    )
    frontend_dir: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent.parent / "frontend" / "out",
        description="Path to statically exported Next.js frontend directory"
    )

    # ---- Forensics & ML Inference ----
    model_path: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent.parent / "shadowmem_model.pkl",
        description="Path to pre-trained scikit-learn model file (.pkl)"
    )
    threshold_malicious: float = Field(70.0, description="Threat score cutoff for Malicious verdict")
    threshold_suspicious: float = Field(35.0, description="Threat score cutoff for Suspicious verdict")
    jit_score_cap: float = Field(25.0, description="Maximum threat score allowed for known JIT runtimes")

    jit_engine_allowlist: Annotated[Set[str], NoDecode] = Field(
        default_factory=lambda: set(DEFAULT_JIT_ENGINE_ALLOWLIST),
        description="Allowlist of known benign JIT engines"
    )
    managed_runtime_names: Annotated[Set[str], NoDecode] = Field(
        default_factory=lambda: set(DEFAULT_MANAGED_RUNTIME_NAMES),
        description="Known managed .NET runtimes"
    )
    managed_runtime_path_prefixes: Annotated[Tuple[str, ...], NoDecode] = Field(
        default_factory=lambda: ("c:\\windows\\",),
        description="Authorized path prefixes for managed runtimes"
    )
    critical_system_processes: Annotated[Set[str], NoDecode] = Field(
        default_factory=lambda: set(DEFAULT_CRITICAL_SYSTEM_PROCESSES),
        description="Protected Windows operating system processes that must never be suspended"
    )

    # ---- WebSocket Alerts & Memory Visualizer ----
    scan_interval_seconds: float = Field(30.0, description="Interval in seconds between ticker memory scans")
    threat_statuses: Annotated[Tuple[str, ...], NoDecode] = Field(
        default_factory=lambda: ("Malicious (Injected)", "Suspicious"),
        description="Verdict statuses that trigger real-time alert broadcasts"
    )
    max_region_details: int = Field(16, description="Max unbacked regions captured per process for visualization")

    # ---- Test-Only Mock Server (tests/mocks/server.py) ----
    mock_port: int = Field(
        8082,
        description="Bind port for the standalone test-only mock server; kept distinct from port "
                    "so the mock can never collide with the authoritative app.py server"
    )

    # ---- Logging ----
    log_level: str = Field("INFO", description="Logging verbosity level (DEBUG, INFO, WARNING, ERROR)")
    log_format: str = Field(
        "%(asctime)s [ShadowMem] %(levelname)s [%(name)s] %(message)s",
        description="Log message format string"
    )

    # ---- Future Integration Points (Docker sandbox & supply chain) ----
    docker_sandbox_enabled: bool = Field(False, description="Enable Docker sandbox execution via WSL2")
    docker_sandbox_wsl_distro: str = Field("Ubuntu", description="WSL2 distribution name for Docker engine")
    supply_chain_scanner_enabled: bool = Field(False, description="Enable automated supply-chain scanner module")

    @field_validator(
        "cors_origins",
        "jit_engine_allowlist",
        "managed_runtime_names",
        "managed_runtime_path_prefixes",
        "critical_system_processes",
        "threat_statuses",
        mode="before",
    )
    @classmethod
    def _coerce_collections(cls, value: Any) -> Any:
        """Accept comma-separated or JSON-array strings for every collection field."""
        if isinstance(value, str):
            return _parse_list_or_set(value)
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: Any) -> Any:
        """Normalize ``SHADOWMEM_LOG_LEVEL=debug`` to ``DEBUG``."""
        return value.upper() if isinstance(value, str) else value

    @classmethod
    def load(cls) -> "Settings":
        """Load settings from environment variables and the .env file.

        Retained as a backwards-compatible alias: with ``BaseSettings`` the
        environment is read on instantiation, so this is ``Settings()``.
        """
        return cls()


# Global singleton instance
settings = Settings()
