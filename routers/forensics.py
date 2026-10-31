"""
routers/forensics.py
====================
API routes for volatile memory forensic scanning, threat posture analysis,
and live memory buffer hex extraction.
Provides /api/v1/scan, /api/v1/memory/dump, and legacy /api/* endpoints.
"""

from typing import Optional
from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse

from schemas.forensics import ScanResponse, MemoryDumpResponse
from services.forensics import (
    get_scan_lock,
    perform_scan_and_diff_locked,
    load_model,
    get_memory_dump,
)
from services.alerts import broadcast_scan_updates
from core.logging import logger

router = APIRouter(tags=["Forensics (v1)"])
compat_router = APIRouter(tags=["Forensics (Compat)"])


@router.get(
    "/scan",
    response_model=ScanResponse,
    summary="Execute full volatile memory scan",
    description="Inspects active Windows processes via Win32 VirtualQueryEx memory traversal and classifies threats using the 7-feature ML model.",
)
@compat_router.get(
    "/api/scan",
    response_model=ScanResponse,
    summary="Execute full volatile memory scan (compat)",
    description="Legacy unversioned endpoint for backward compatibility with existing frontends and scripts.",
)
def api_scan(background_tasks: BackgroundTasks) -> JSONResponse:
    """Execute volatile memory traversal, compute ML threat scores, and return findings."""
    scan_lock = get_scan_lock()
    try:
        with scan_lock:
            evaluated, changes = perform_scan_and_diff_locked()
    except RuntimeError as rerr:
        raise HTTPException(status_code=503, detail=str(rerr)) from rerr
    except Exception as exc:  # noqa: BLE001
        logger.error("memory scan failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Memory scan failed: {exc}") from exc

    model = load_model()
    total_scanned = len(evaluated)
    anomalies = [p for p in evaluated if p["status"] in ("Malicious (Injected)", "Suspicious")]
    malicious_count = sum(1 for p in evaluated if p["status"] == "Malicious (Injected)")
    suspicious_count = sum(1 for p in evaluated if p["status"] == "Suspicious")
    jit_count = sum(1 for p in evaluated if p["status"] == "Legitimate JIT Engine")
    clean_count = total_scanned - malicious_count - suspicious_count - jit_count
    posture = "Threat Detected" if malicious_count > 0 else "Protected"

    # Push scan updates to connected dashboards as a background task
    background_tasks.add_task(broadcast_scan_updates, changes)

    return JSONResponse({
        "summary": {
            "total_scanned": total_scanned,
            "anomalies_detected": len(anomalies),
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "jit_engine_count": jit_count,
            "clean_count": clean_count,
            "system_posture": posture,
            "model_loaded": model is not None,
        },
        "processes": evaluated,
    })


@router.get(
    "/memory/dump/{pid}",
    response_model=MemoryDumpResponse,
    summary="Inspect process memory buffer",
    description="Extracts and formats the first unbacked executable memory slice for a target process with Shannon entropy and hex disassembly.",
)
@compat_router.get(
    "/api/memory/dump/{pid}",
    response_model=MemoryDumpResponse,
    summary="Inspect process memory buffer (compat)",
    description="Legacy unversioned memory buffer dump endpoint.",
)
def api_memory_dump(pid: int) -> JSONResponse:
    """Extract memory dump for PID."""
    dump_data = get_memory_dump(pid)
    return JSONResponse(dump_data)


@router.get(
    "/memory/dump/{pid}/{address}",
    response_model=MemoryDumpResponse,
    summary="Inspect specific memory address buffer",
    description="Extracts and formats memory slice at a specific base address for a target process.",
)
@compat_router.get(
    "/api/memory/dump/{pid}/{address}",
    response_model=MemoryDumpResponse,
    summary="Inspect specific memory address buffer (compat)",
    description="Legacy unversioned memory buffer dump endpoint for specific address.",
)
def api_memory_dump_address(pid: int, address: str) -> JSONResponse:
    """Extract memory dump for PID and specific address."""
    dump_data = get_memory_dump(pid, address)
    return JSONResponse(dump_data)
