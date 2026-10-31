"""
routers/supply_chain.py
=======================
API endpoints for software supply chain analysis and loaded module integrity verification.
"""

from fastapi import APIRouter, HTTPException

from schemas.supply_chain import (
    SupplyChainScanRequest,
    SupplyChainScanResponse,
    SupplyChainHealthResponse,
)
from services.supply_chain import (
    scan_process_modules,
    scan_directory_modules,
    get_supply_chain_health,
)

router = APIRouter(prefix="/supply-chain", tags=["Supply Chain (v1)"])
compat_router = APIRouter(prefix="/api/supply-chain", tags=["Supply Chain (Compat)"])


@router.get(
    "/health",
    response_model=SupplyChainHealthResponse,
    summary="Check supply chain scanner health",
    description="Inspects availability of binary inspection engines and signature verification libraries.",
)
@compat_router.get(
    "/health",
    response_model=SupplyChainHealthResponse,
    summary="Check supply chain scanner health (compat)",
)
def api_supply_chain_health() -> SupplyChainHealthResponse:
    """Return health and capabilities of the supply chain scanner subsystem."""
    return get_supply_chain_health()


@router.post(
    "/scan/process/{pid}",
    response_model=SupplyChainScanResponse,
    summary="Scan loaded modules of active process",
    description="Enumerates all memory-mapped DLLs and modules for a running process and verifies signatures.",
)
@compat_router.post(
    "/scan/process/{pid}",
    response_model=SupplyChainScanResponse,
    summary="Scan loaded modules of active process (compat)",
)
def api_scan_process(pid: int) -> SupplyChainScanResponse:
    """Evaluate module signatures and supply chain posture for a live Windows process."""
    if pid <= 0:
        raise HTTPException(status_code=400, detail="Invalid process PID.")
    return scan_process_modules(pid)


@router.post(
    "/scan/path",
    response_model=SupplyChainScanResponse,
    summary="Scan filesystem directory or binary file",
    description="Inspects binary files on disk for digital signatures, hashes, and potential supply-chain tampering.",
)
@compat_router.post(
    "/scan/path",
    response_model=SupplyChainScanResponse,
    summary="Scan filesystem directory or binary file (compat)",
)
def api_scan_path(req: SupplyChainScanRequest) -> SupplyChainScanResponse:
    """Evaluate binaries in a specific directory or process."""
    if req.pid is not None and req.pid > 0:
        return scan_process_modules(req.pid)
    if req.target_path:
        return scan_directory_modules(req.target_path)
    raise HTTPException(status_code=400, detail="Must provide either 'pid' or 'target_path'.")
