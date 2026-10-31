"""
tests/test_config_settings.py
=============================
Automated test suite for Step 3:
1. Default configuration values and schema validation
2. Environment variable overrides via SHADOWMEM_ prefix
3. Root config re-export and structured logging
4. App integration consistency
"""

import os
import sys
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import (
    Settings,
    settings,
    DEFAULT_JIT_ENGINE_ALLOWLIST,
    DEFAULT_MANAGED_RUNTIME_NAMES,
    DEFAULT_CRITICAL_SYSTEM_PROCESSES,
)
from core.logging import setup_logging, get_logger, logger
import config


def test_default_settings():
    s = Settings()
    assert s.app_title == "ShadowMem"
    assert s.port == 8000
    assert s.api_prefix == "/api/v1"
    assert s.threshold_malicious == 70.0
    assert s.threshold_suspicious == 35.0
    assert s.jit_score_cap == 25.0
    assert s.scan_interval_seconds == 30.0
    assert "chrome.exe" in s.jit_engine_allowlist
    assert "csrss.exe" in s.critical_system_processes
    assert "powershell.exe" in s.managed_runtime_names
    assert s.docker_sandbox_enabled is False
    assert s.supply_chain_scanner_enabled is False


def test_environment_variable_overrides():
    env_backup = dict(os.environ)
    try:
        os.environ["SHADOWMEM_PORT"] = "9090"
        os.environ["SHADOWMEM_HOST"] = "127.0.0.1"
        os.environ["SHADOWMEM_THRESHOLD_MALICIOUS"] = "82.5"
        os.environ["SHADOWMEM_THRESHOLD_SUSPICIOUS"] = "40.0"
        os.environ["SHADOWMEM_SCAN_INTERVAL_SECONDS"] = "15.0"
        os.environ["SHADOWMEM_CORS_ORIGINS"] = "http://localhost:3000, http://127.0.0.1:3000"
        os.environ["SHADOWMEM_LOG_LEVEL"] = "debug"
        os.environ["SHADOWMEM_DOCKER_SANDBOX_ENABLED"] = "true"

        custom = Settings.load()
        assert custom.port == 9090
        assert custom.host == "127.0.0.1"
        assert custom.threshold_malicious == 82.5
        assert custom.threshold_suspicious == 40.0
        assert custom.scan_interval_seconds == 15.0
        assert custom.cors_origins == ["http://localhost:3000", "http://127.0.0.1:3000"]
        assert custom.log_level == "DEBUG"
        assert custom.docker_sandbox_enabled is True
    finally:
        os.environ.clear()
        os.environ.update(env_backup)


def test_root_config_reexport():
    assert config.settings is settings
    assert config.Settings is Settings


def test_structured_logging():
    test_logger = get_logger("shadowmem.test")
    assert test_logger is not None
    test_logger.info("Structured logging test message: %s", "ok")

    configured = setup_logging(log_level="INFO")
    assert configured.name == "shadowmem"


def test_app_integration_consistency():
    from app import (
        app,
        MODEL_PATH,
        THRESHOLD_MALICIOUS,
        THRESHOLD_SUSPICIOUS,
        JIT_SCORE_CAP,
        JIT_ENGINE_ALLOWLIST,
        CRITICAL_SYSTEM_PROCESSES,
        SCAN_INTERVAL_SECONDS,
    )

    assert MODEL_PATH == settings.model_path
    assert THRESHOLD_MALICIOUS == settings.threshold_malicious
    assert THRESHOLD_SUSPICIOUS == settings.threshold_suspicious
    assert JIT_SCORE_CAP == settings.jit_score_cap
    assert JIT_ENGINE_ALLOWLIST == settings.jit_engine_allowlist
    assert CRITICAL_SYSTEM_PROCESSES == settings.critical_system_processes
    assert SCAN_INTERVAL_SECONDS == settings.scan_interval_seconds

    assert app.title == settings.app_title
    assert app.description == settings.app_description
    assert app.version == settings.app_version


if __name__ == "__main__":
    print("Running Step 3 test suite...")
    test_default_settings()
    test_environment_variable_overrides()
    test_root_config_reexport()
    test_structured_logging()
    test_app_integration_consistency()
    print("ALL STEP 3 CONFIG & LOGGING TESTS PASSED SUCCESSFULLY!")
