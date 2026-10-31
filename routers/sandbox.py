"""
routers/sandbox.py
==================
API endpoints for Docker WSL2 malware detonation sandbox.
"""

from typing import List
from fastapi import APIRouter, HTTPException

from schemas.sandbox import (
    SandboxSubmissionRequest,
    SandboxExecutionResult,
    SandboxHealthResponse,
)
from services.sandbox import (
    get_sandbox_health,
    submit_sample_job,
    get_job_result,
    list_jobs,
)

router = APIRouter(prefix="/sandbox", tags=["Sandbox (v1)"])
compat_router = APIRouter(prefix="/api/sandbox", tags=["Sandbox (Compat)"])


@router.get(
    "/health",
    response_model=SandboxHealthResponse,
    summary="Check Docker & WSL2 sandbox readiness",
    description="Inspects availability of Windows Subsystem for Linux (WSL2) and Docker daemon.",
)
@compat_router.get(
    "/health",
    response_model=SandboxHealthResponse,
    summary="Check Docker & WSL2 sandbox readiness (compat)",
)
def api_sandbox_health() -> SandboxHealthResponse:
    """Return virtualization layer health and readiness status."""
    return get_sandbox_health()


@router.post(
    "/submit",
    response_model=SandboxExecutionResult,
    summary="Submit executable sample for sandboxed detonation",
    description="Submits a binary for isolated analysis in a secure Docker container over WSL2.",
)
@compat_router.post(
    "/submit",
    response_model=SandboxExecutionResult,
    summary="Submit executable sample for sandboxed detonation (compat)",
)
def api_sandbox_submit(req: SandboxSubmissionRequest) -> SandboxExecutionResult:
    """Queue or execute a sandbox analysis run."""
    return submit_sample_job(req)


@router.get(
    "/status/{job_id}",
    response_model=SandboxExecutionResult,
    summary="Retrieve sandbox execution results",
    description="Returns telemetry, exit code, memory anomalies, and artifacts from a completed sandbox run.",
)
@compat_router.get(
    "/status/{job_id}",
    response_model=SandboxExecutionResult,
    summary="Retrieve sandbox execution results (compat)",
)
def api_sandbox_status(job_id: str) -> SandboxExecutionResult:
    """Lookup result of a submitted sandbox job."""
    res = get_job_result(job_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Sandbox job '{job_id}' not found.")
    return res


@router.get(
    "/jobs",
    response_model=List[SandboxExecutionResult],
    summary="List recent sandbox jobs",
)
@compat_router.get(
    "/jobs",
    response_model=List[SandboxExecutionResult],
    summary="List recent sandbox jobs (compat)",
)
def api_sandbox_list_jobs() -> List[SandboxExecutionResult]:
    """Return all known sandbox jobs."""
    return list_jobs()
