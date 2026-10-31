"""
routers/containment.py
======================
API routes for active threat containment (process thread suspension/resumption)
and containment audit history.
"""

from typing import Optional
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from schemas.containment import (
    IsolateRequest,
    ContainmentResponse,
    AuditResponse,
)
from services.containment import (
    isolate_process,
    resume_process,
    get_audit_trail,
)

router = APIRouter(tags=["Containment (v1)"])
compat_router = APIRouter(tags=["Containment (Compat)"])


@router.post(
    "/isolate/{pid}",
    response_model=ContainmentResponse,
    summary="Suspend process threads (containment)",
    description="Suspends all threads in a target user-mode process using OpenThread + SuspendThread. Protected system processes are safeguarded.",
)
@compat_router.post(
    "/api/isolate/{pid}",
    response_model=ContainmentResponse,
    summary="Suspend process threads (compat)",
    description="Legacy unversioned containment endpoint for backward compatibility.",
)
def api_isolate(pid: int, body: Optional[IsolateRequest] = None, reason: str = "") -> JSONResponse:
    """Suspend every thread in a target user-mode process."""
    effective_reason = (body.reason if body and body.reason else reason) or ""
    status_code, response_data = isolate_process(pid, effective_reason)
    return JSONResponse(response_data, status_code=status_code)


@router.post(
    "/resume/{pid}",
    response_model=ContainmentResponse,
    summary="Resume suspended process threads",
    description="Resumes threads in a target user-mode process previously suspended via isolation.",
)
@compat_router.post(
    "/api/resume/{pid}",
    response_model=ContainmentResponse,
    summary="Resume suspended process threads (compat)",
    description="Legacy unversioned endpoint for backward compatibility.",
)
def api_resume(pid: int) -> JSONResponse:
    """Resume a previously-suspended process (undo isolation)."""
    status_code, response_data = resume_process(pid)
    return JSONResponse(response_data, status_code=status_code)


@router.get(
    "/audit",
    response_model=AuditResponse,
    summary="Retrieve containment audit trail",
    description="Returns the in-memory audit log of all process isolation and resumption actions.",
)
@compat_router.get(
    "/api/audit",
    response_model=AuditResponse,
    summary="Retrieve containment audit trail (compat)",
    description="Legacy unversioned audit endpoint for backward compatibility.",
)
def api_audit() -> JSONResponse:
    """Return the in-memory audit trail for isolate and resume actions."""
    return JSONResponse({"actions": get_audit_trail()})
