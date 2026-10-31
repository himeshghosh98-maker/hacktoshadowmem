"""
tests/test_step5_integrations.py
================================
Automated verification suite for Step 5:
1. Docker Sandbox (WSL2) schemas, service layer, and API endpoints
2. Supply Chain & Module Integrity schemas, service layer, and API endpoints
3. ASGI endpoint compliance for versioned /api/v1/ and compat routes
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app
from schemas.sandbox import (
    SandboxSubmissionRequest,
    SandboxExecutionResult,
    SandboxHealthResponse,
)
from schemas.supply_chain import (
    ModuleIntegrityFinding,
    SupplyChainScanRequest,
    SupplyChainScanResponse,
    SupplyChainHealthResponse,
)
from services.sandbox import (
    get_sandbox_health,
    submit_sample_job,
    get_job_result,
    list_jobs,
)
from services.supply_chain import (
    get_supply_chain_health,
    compute_sha256,
    is_binary_signed,
    is_suspicious_filepath,
    inspect_module_file,
    scan_process_modules,
    scan_directory_modules,
)


# ============================================================================
# 1. Sandbox Service & Schemas
# ============================================================================

def test_sandbox_service_and_schemas():
    health = get_sandbox_health()
    assert isinstance(health, SandboxHealthResponse)
    assert health.wsl_distro == "Ubuntu"

    # Submit sample job
    req = SandboxSubmissionRequest(
        sample_name="trojan_dropper.exe",
        arguments=["--silent"],
        timeout_seconds=30,
    )
    job = submit_sample_job(req)
    assert isinstance(job, SandboxExecutionResult)
    assert job.job_id is not None
    assert job.status in ("disabled", "failed", "completed")

    # Retrieve job
    retrieved = get_job_result(job.job_id)
    assert retrieved is not None
    assert retrieved.job_id == job.job_id

    # List jobs
    all_jobs = list_jobs()
    assert len(all_jobs) >= 1


# ============================================================================
# 2. Supply Chain Service & Schemas
# ============================================================================

def test_supply_chain_service_and_schemas():
    health = get_supply_chain_health()
    assert isinstance(health, SupplyChainHealthResponse)
    assert health.pefile_available is True

    # Test hash computation
    system32_kernel = r"C:\Windows\System32\kernel32.dll"
    if os.path.isfile(system32_kernel):
        digest = compute_sha256(system32_kernel)
        assert len(digest) == 64
        assert digest != "UNKNOWN_HASH"

        # Test signature verification
        is_signed, signer = is_binary_signed(system32_kernel)
        assert is_signed is True
        assert signer is not None

        # Inspect module file
        finding = inspect_module_file(system32_kernel)
        assert finding.module_name.lower() == "kernel32.dll"
        assert finding.is_signed is True
        assert finding.is_suspicious_location is False

    # Test suspicious path heuristic
    assert is_suspicious_filepath(r"C:\Users\Analyst\AppData\Local\Temp\payload.dll") is True
    assert is_suspicious_filepath(r"C:\Windows\System32\ntdll.dll") is False

    # Test process module scan on our current running process
    our_pid = os.getpid()
    proc_scan = scan_process_modules(our_pid)
    assert isinstance(proc_scan, SupplyChainScanResponse)
    assert proc_scan.total_modules_scanned > 0
    assert proc_scan.posture in ("Protected", "Suspicious", "Vulnerable")


# ============================================================================
# 3. ASGI Endpoint Verification
# ============================================================================

async def _call_asgi(method: str, path: str, body: dict = None):
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
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


def test_sandbox_endpoints():
    async def run():
        # Health endpoint
        s1, r1 = await _call_asgi("GET", "/api/v1/sandbox/health")
        s2, r2 = await _call_asgi("GET", "/api/sandbox/health")
        assert s1 == 200 and s2 == 200
        SandboxHealthResponse.model_validate(r1)

        # Submit endpoint
        payload = {"sample_name": "test_injector.exe", "arguments": ["-v"]}
        s_sub, r_sub = await _call_asgi("POST", "/api/v1/sandbox/submit", payload)
        assert s_sub == 200
        job_res = SandboxExecutionResult.model_validate(r_sub)

        # Status endpoint
        s_stat, r_stat = await _call_asgi("GET", f"/api/v1/sandbox/status/{job_res.job_id}")
        assert s_stat == 200
        assert r_stat["job_id"] == job_res.job_id

        # Jobs list endpoint
        s_jobs, r_jobs = await _call_asgi("GET", "/api/v1/sandbox/jobs")
        assert s_jobs == 200
        assert len(r_jobs) >= 1

    asyncio.run(run())


def test_supply_chain_endpoints():
    async def run():
        # Health endpoint
        s1, r1 = await _call_asgi("GET", "/api/v1/supply-chain/health")
        s2, r2 = await _call_asgi("GET", "/api/supply-chain/health")
        assert s1 == 200 and s2 == 200
        SupplyChainHealthResponse.model_validate(r1)

        # Scan our own live process
        our_pid = os.getpid()
        s_proc, r_proc = await _call_asgi("POST", f"/api/v1/supply-chain/scan/process/{our_pid}")
        assert s_proc == 200
        proc_resp = SupplyChainScanResponse.model_validate(r_proc)
        assert proc_resp.total_modules_scanned > 0

        # Scan directory / path
        s_path, r_path = await _call_asgi("POST", "/api/v1/supply-chain/scan/path", {"target_path": r"C:\Windows\System32"})
        assert s_path == 200
        path_resp = SupplyChainScanResponse.model_validate(r_path)
        assert path_resp.total_modules_scanned > 0

    asyncio.run(run())


if __name__ == "__main__":
    print("Running Step 5 Integration test suite...")
    test_sandbox_service_and_schemas()
    test_supply_chain_service_and_schemas()
    test_sandbox_endpoints()
    test_supply_chain_endpoints()
    print("ALL STEP 5 INTEGRATION TESTS PASSED SUCCESSFULLY!")
