"""
tests/test_layered_architecture.py
==================================
Verification suite for Step 4 Layered Architecture:
1. Services isolation (forensics, containment, alerts)
2. Routers structure and route registrations
3. app.py coordinator cleanliness and backward compatibility re-exports
"""

import sys
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.forensics import (
    load_model,
    classify_score,
    is_jit_engine,
    is_benign_managed_runtime,
    evaluate_process,
    get_cached_processes,
    get_scan_lock,
)
from services.containment import (
    isolate_process,
    resume_process,
    get_audit_trail,
    record_audit,
)
from services.alerts import (
    ws_manager,
    build_memory_map,
    threat_alert_frame,
    SIMULATE_SCENARIOS,
)
from routers import (
    v1_router,
    compat_router,
    forensics_v1_router,
    containment_v1_router,
    alerts_v1_router,
)
import app


def test_services_isolation():
    # Forensics service functions callable in isolation
    assert classify_score(80.0) == "Malicious (Injected)"
    assert classify_score(45.0) == "Suspicious"
    assert classify_score(10.0) == "Clean"

    assert is_jit_engine("chrome.exe") is True
    assert is_jit_engine("malware.exe") is False

    assert is_benign_managed_runtime("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe") is True
    assert is_benign_managed_runtime("powershell.exe", r"C:\Users\User\AppData\Local\Temp\powershell.exe") is False

    mock_proc = {
        "pid": 5000,
        "name": "calc.exe",
        "rwx_count": 0,
        "unbacked_exec_count": 0,
        "total_rwx_bytes": 0,
        "num_threads": 1,
        "thread_unbacked_start": 0,
        "vad_protection_anomaly": 0,
    }
    evaluated = evaluate_process(mock_proc, model=None)
    assert evaluated["pid"] == 5000
    assert evaluated["status"] == "Clean"
    assert evaluated["threat_score"] == 0.0

    # Containment service functions callable in isolation
    s_iso, res_iso = isolate_process(0)
    assert s_iso == 400
    assert res_iso["success"] is False

    s_res, res_res = resume_process(0)
    assert s_res == 400
    assert res_res["success"] is False

    record_audit(1111, "test.exe", "isolate", True, "audit check")
    trail = get_audit_trail()
    assert any(a["pid"] == 1111 for a in trail)

    # Alerts service functions callable in isolation
    mmap = build_memory_map([])
    assert mmap["type"] == "memory_map"
    assert "blocks" in mmap

    frame = threat_alert_frame({"pid": 999, "name": "bad.exe", "status": "Malicious (Injected)", "threat_score": 90.0}, None)
    assert frame["type"] == "alert"
    assert frame["severity"] == "critical"


def _extract_paths(router):
    paths = []
    for r in router.routes:
        if hasattr(r, "path"):
            paths.append(r.path)
        elif hasattr(r, "original_router"):
            for sub in r.original_router.routes:
                paths.append(sub.path)
        elif hasattr(r, "routes"):
            for sub in r.routes:
                paths.append(sub.path)
    return paths


def test_routers_structure():
    # Check v1_router routes
    v1_routes = _extract_paths(v1_router)
    assert "/scan" in v1_routes
    assert "/isolate/{pid}" in v1_routes
    assert "/resume/{pid}" in v1_routes
    assert "/audit" in v1_routes
    assert "/simulate/alert" in v1_routes
    assert "/ws/alerts" in v1_routes

    # Check compat_router routes
    compat_routes = _extract_paths(compat_router)
    assert "/api/scan" in compat_routes
    assert "/api/isolate/{pid}" in compat_routes
    assert "/api/resume/{pid}" in compat_routes
    assert "/api/audit" in compat_routes
    assert "/simulate/alert" in compat_routes
    assert "/ws/alerts" in compat_routes


def test_app_coordinator_cleanliness():
    app_py_path = Path(app.__file__)
    line_count = len(app_py_path.read_text(encoding="utf-8").splitlines())

    # Verify app.py is under 200 lines (was 3,800+ lines before refactor)
    assert line_count < 200, f"app.py should be under 200 lines, but is {line_count}"

    # Verify backward compatibility re-exports on app module
    assert hasattr(app, "all_processes")
    assert hasattr(app, "MODEL_PATH")
    assert hasattr(app, "THRESHOLD_MALICIOUS")
    assert hasattr(app, "CRITICAL_SYSTEM_PROCESSES")
    assert hasattr(app, "api_scan")
    assert hasattr(app, "api_isolate")
    assert hasattr(app, "api_resume")
    assert hasattr(app, "api_audit")
    assert hasattr(app, "simulate_alert")
    assert hasattr(app, "websocket_alerts")
    assert hasattr(app, "INDEX_HTML")

    # Verify fallback template was loaded
    assert len(app.INDEX_HTML) > 1000
    assert "scanBtn.addEventListener" in app.INDEX_HTML


if __name__ == "__main__":
    print("Running Step 4 Layered Architecture test suite...")
    test_services_isolation()
    test_routers_structure()
    test_app_coordinator_cleanliness()
    print("ALL STEP 4 LAYERED ARCHITECTURE TESTS PASSED SUCCESSFULLY!")
