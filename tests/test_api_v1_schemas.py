"""
tests/test_api_v1_schemas.py
============================
Automated verification suite for Step 2:
1. Pydantic request & response schema validation
2. FastAPI OpenAPI spec verification for /api/v1 and legacy endpoints
3. ASGI request/response compliance for versioned and compat routes
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pydantic import ValidationError

from app import app
from schemas import (
    ProcessClassification,
    UnbackedRegion,
    ProcessEntry,
    ScanSummary,
    ScanResponse,
    IsolateRequest,
    ContainmentResponse,
    AuditAction,
    AuditResponse,
    SimulateAlertRequest,
    SimulateAlertResponse,
    AlertFrame,
    MemoryBlock,
    MemoryMapFrame,
)


# ============================================================================
# 1. Pydantic Model Integrity Tests
# ============================================================================

def test_process_entry_schema():
    entry_data = {
        "pid": 1234,
        "name": "beacon.exe",
        "exe": "C:\\malware\\beacon.exe",
        "rwx_count": 2,
        "unbacked_exec_count": 1,
        "total_rwx_bytes": 65536,
        "allocated_kb": 64.0,
        "num_threads": 4,
        "thread_unbacked_start": 1,
        "vad_protection_anomaly": 1,
        "threat_score": 95.5,
        "status": "Malicious (Injected)",
        "jit_engine": False,
        "model_used": True,
        "classification": {
            "mitre_id": "T1620",
            "display_name": "Reflective Code Loading",
            "short_description": "Reflective DLL injection detected.",
            "typical_indicators": "RWX unbacked memory",
            "recommended_response": "Isolate process immediately."
        },
        "unbacked_regions": [
            {"base_address": "0x7ffa0000", "size": 4096, "protection": "PAGE_EXECUTE_READWRITE"}
        ]
    }
    model = ProcessEntry.model_validate(entry_data)
    assert model.pid == 1234
    assert model.classification.mitre_id == "T1620"
    assert len(model.unbacked_regions) == 1
    assert model.unbacked_regions[0].base_address == "0x7ffa0000"


def test_scan_response_schema():
    scan_data = {
        "summary": {
            "total_scanned": 150,
            "anomalies_detected": 1,
            "malicious_count": 1,
            "suspicious_count": 0,
            "jit_engine_count": 5,
            "clean_count": 144,
            "system_posture": "Threat Detected",
            "model_loaded": True
        },
        "processes": []
    }
    model = ScanResponse.model_validate(scan_data)
    assert model.summary.total_scanned == 150
    assert model.summary.system_posture == "Threat Detected"
    assert model.processes == []


def test_containment_response_schema():
    # Success response
    resp = ContainmentResponse(
        pid=456,
        name="test.exe",
        action="suspended",
        success=True,
        suspended_count=3,
        failed_count=0
    )
    assert resp.success is True
    assert resp.action == "suspended"

    # Error response without pid/name
    err_resp = ContainmentResponse(
        action="suspended",
        success=False,
        error="Invalid PID."
    )
    assert err_resp.success is False
    assert err_resp.pid is None


def test_simulate_alert_schema_validation():
    req = SimulateAlertRequest(
        scenario="cobalt_strike_reflective_injection",
        severity="critical"
    )
    assert req.scenario == "cobalt_strike_reflective_injection"
    assert req.severity == "critical"

    # Severity is required
    try:
        SimulateAlertRequest()
        assert False, "Should fail when severity is omitted"
    except ValidationError:
        pass


def test_alert_frame_and_memory_map():
    alert = AlertFrame(
        event_id="evt-100",
        timestamp="2026-10-11T12:00:00Z",
        severity="critical",
        process={"pid": 1234, "name": "rundll32.exe"},
        detection={
            "is_malicious": True,
            "confidence": 0.95,
            "technique": "T1620 — Reflective Loading"
        },
        message="Simulated injection detected"
    )
    assert alert.event_id == "evt-100"
    assert alert.severity == "critical"

    mmap = MemoryMapFrame(
        event_id="mmap-100",
        timestamp="2026-10-11T12:00:00Z",
        blocks=[
            MemoryBlock(
                index=0,
                base_address="0x1000",
                size=4096,
                protection="PAGE_EXECUTE_READWRITE",
                status="infected"
            )
        ]
    )
    assert len(mmap.blocks) == 1
    assert mmap.blocks[0].status == "infected"


# ============================================================================
# 2. OpenAPI Specification Verification
# ============================================================================

def test_openapi_schema_completeness():
    spec = app.openapi()
    paths = spec["paths"]

    # Check v1 endpoints exist
    assert "/api/v1/scan" in paths
    assert "/api/v1/isolate/{pid}" in paths
    assert "/api/v1/resume/{pid}" in paths
    assert "/api/v1/audit" in paths
    assert "/api/v1/simulate/alert" in paths

    # Check legacy compatibility endpoints exist
    assert "/api/scan" in paths
    assert "/api/isolate/{pid}" in paths
    assert "/api/resume/{pid}" in paths
    assert "/api/audit" in paths
    assert "/simulate/alert" in paths

    # Verify Pydantic components are documented
    components = spec.get("components", {}).get("schemas", {})
    expected_schemas = [
        "ScanResponse",
        "ScanSummary",
        "ProcessEntry",
        "ContainmentResponse",
        "AuditResponse",
        "AuditAction",
        "SimulateAlertRequest",
        "SimulateAlertResponse",
    ]
    for s in expected_schemas:
        assert s in components, f"Missing schema in OpenAPI components: {s}"


# ============================================================================
# 3. ASGI Endpoint Request/Response Tests
# ============================================================================

async def _call_asgi(method: str, path: str, body: dict = None, query: str = ""):
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": query.encode(),
        "headers": [(b"content-type", b"application/json"), (b"host", b"localhost")],
    }
    body_bytes = json.dumps(body).encode() if body is not None else b""
    sent = False
    status_code = None
    response_body = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body_bytes, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        nonlocal status_code
        if message["type"] == "http.response.start":
            status_code = message["status"]
        elif message["type"] == "http.response.body":
            response_body.append(message.get("body", b""))

    await app(scope, receive, send)
    resp_text = b"".join(response_body).decode()
    try:
        data = json.loads(resp_text)
    except Exception:
        data = resp_text
    return status_code, data


def test_audit_endpoints_v1_and_compat():
    async def run():
        s_compat, r_compat = await _call_asgi("GET", "/api/audit")
        s_v1, r_v1 = await _call_asgi("GET", "/api/v1/audit")

        assert s_compat == 200
        assert s_v1 == 200
        assert "actions" in r_compat
        assert "actions" in r_v1
        AuditResponse.model_validate(r_compat)
        AuditResponse.model_validate(r_v1)

    asyncio.run(run())


def test_simulate_alert_v1_and_compat():
    async def run():
        payload = {
            "scenario": "cobalt_strike_reflective_injection",
            "severity": "critical"
        }
        s_compat, r_compat = await _call_asgi("POST", "/simulate/alert", payload)
        s_v1, r_v1 = await _call_asgi("POST", "/api/v1/simulate/alert", payload)

        assert s_compat == 200
        assert s_v1 == 200
        SimulateAlertResponse.model_validate(r_compat)
        SimulateAlertResponse.model_validate(r_v1)
        assert r_compat["scenario"] == "cobalt_strike_reflective_injection"
        assert r_v1["scenario"] == "cobalt_strike_reflective_injection"

        # Test invalid scenario -> 400
        bad_scenario = {"scenario": "fake_pattern", "severity": "info"}
        s_bad, r_bad = await _call_asgi("POST", "/api/v1/simulate/alert", bad_scenario)
        assert s_bad == 400

        # Test missing severity -> 422
        bad_req = {"scenario": "dll_injection"}
        s_422, r_422 = await _call_asgi("POST", "/api/v1/simulate/alert", bad_req)
        assert s_422 == 422

    asyncio.run(run())


def test_containment_validation():
    async def run():
        # Negative PID -> 400
        s1, r1 = await _call_asgi("POST", "/api/v1/isolate/0")
        assert s1 == 400
        ContainmentResponse.model_validate(r1)
        assert r1["success"] is False

        # Nonexistent PID -> 404
        s2, r2 = await _call_asgi("POST", "/api/v1/isolate/99999", {"reason": "test isolation"})
        assert s2 == 404
        ContainmentResponse.model_validate(r2)
        assert r2["success"] is False

        # Resume nonexistent PID -> 404
        s3, r3 = await _call_asgi("POST", "/api/v1/resume/99999")
        assert s3 == 404
        ContainmentResponse.model_validate(r3)
        assert r3["success"] is False

    asyncio.run(run())


def test_scan_endpoints():
    async def run():
        # Execute live scan on both endpoints
        s_compat, r_compat = await _call_asgi("GET", "/api/scan")
        s_v1, r_v1 = await _call_asgi("GET", "/api/v1/scan")

        assert s_compat == 200
        assert s_v1 == 200
        resp_model_compat = ScanResponse.model_validate(r_compat)
        resp_model_v1 = ScanResponse.model_validate(r_v1)

        assert resp_model_compat.summary.total_scanned > 0
        assert resp_model_v1.summary.total_scanned > 0
        assert resp_model_v1.summary.system_posture in ("Protected", "Threat Detected")

    asyncio.run(run())


if __name__ == "__main__":
    print("Running test suite directly...")
    test_process_entry_schema()
    test_scan_response_schema()
    test_containment_response_schema()
    test_simulate_alert_schema_validation()
    test_alert_frame_and_memory_map()
    test_openapi_schema_completeness()
    test_audit_endpoints_v1_and_compat()
    test_simulate_alert_v1_and_compat()
    test_containment_validation()
    test_scan_endpoints()
    print("ALL STEP 2 API & SCHEMA TESTS PASSED SUCCESSFULLY!")
