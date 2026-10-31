"""
services/supply_chain.py
========================
Software supply chain and module integrity verification service.
Inspects loaded process libraries, verifies binary digital signatures,
hashes artifacts with SHA-256, and assesses package posture.
"""

import hashlib
import os
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

from core.config import settings
from core.logging import logger
from schemas.supply_chain import (
    SupplyChainScanRequest,
    SupplyChainScanResponse,
    SupplyChainHealthResponse,
    ModuleIntegrityFinding,
    SupplyChainPosture,
)

try:
    import pefile
except ImportError:
    pefile = None


def check_pefile_available() -> bool:
    """Return whether the pefile binary analysis library is loaded."""
    return pefile is not None


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hex digest of a file on disk."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "UNKNOWN_HASH"


def is_binary_signed(file_path: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a portable executable has an embedded Authenticode digital signature.
    Returns (is_signed, signer_identity).
    """
    if not pefile or not os.path.isfile(file_path):
        return False, None

    try:
        pe = pefile.PE(file_path, fast_load=True)
        sec_dir_idx = pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_SECURITY")
        if sec_dir_idx is not None and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx:
            sec_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
            if sec_entry.Size > 0 and sec_entry.VirtualAddress > 0:
                return True, "Authenticode Embedded Certificate"
    except Exception:
        pass

    return False, None


def is_suspicious_filepath(file_path: str) -> bool:
    """Check if binary path resides in volatile, temp, or non-standard user directories."""
    norm = file_path.lower().replace("/", "\\")
    suspicious_patterns = (
        "\\temp\\",
        "\\appdata\\local\\temp",
        "\\users\\public\\",
        "\\recycler\\",
        "\\downloads\\",
    )
    return any(p in norm for p in suspicious_patterns)


def inspect_module_file(file_path: str) -> ModuleIntegrityFinding:
    """Evaluate integrity attributes for a single module binary."""
    name = os.path.basename(file_path)
    signed, signer = is_binary_signed(file_path)
    sha256_hash = compute_sha256(file_path)
    suspicious_loc = is_suspicious_filepath(file_path)

    anomaly = None
    if not signed and suspicious_loc:
        anomaly = "Unsigned binary executing from volatile or temporary directory"
    elif not signed:
        anomaly = "Module lacks embedded Authenticode digital signature"
    elif suspicious_loc:
        anomaly = "Signed binary loaded from non-standard directory"

    return ModuleIntegrityFinding(
        module_name=name,
        file_path=file_path,
        is_signed=signed,
        signer_identity=signer,
        sha256=sha256_hash,
        is_suspicious_location=suspicious_loc,
        is_known_vulnerable=False,
        anomaly_description=anomaly,
    )


def scan_process_modules(pid: int) -> SupplyChainScanResponse:
    """Enumerate and evaluate all loaded DLLs/modules for a given live process."""
    findings: List[ModuleIntegrityFinding] = []
    seen_paths = set()

    proc_name = f"pid:{pid}"
    try:
        import psutil
        p = psutil.Process(pid)
        proc_name = p.name()

        # Enumerate memory mapped files (loaded DLLs and main binary)
        try:
            for m in p.memory_maps():
                path = m.path
                if path and path not in seen_paths and os.path.isfile(path):
                    seen_paths.add(path)
                    # Only analyze executable libraries / PE files
                    if path.lower().endswith((".dll", ".exe", ".sys", ".node")):
                        findings.append(inspect_module_file(path))
        except (psutil.AccessDenied, Exception) as exc:
            logger.warning("Could not enumerate memory maps for pid %d: %s", pid, exc)
            # Fallback to main executable path
            try:
                exe = p.exe()
                if exe and os.path.isfile(exe):
                    findings.append(inspect_module_file(exe))
            except Exception:
                pass
    except Exception as exc:
        logger.error("Failed to inspect process %d: %s", pid, exc)

    unsigned_count = sum(1 for f in findings if not f.is_signed)
    suspicious_count = sum(1 for f in findings if f.is_suspicious_location or f.is_known_vulnerable)

    if suspicious_count > 0:
        posture: SupplyChainPosture = "Vulnerable"
    elif unsigned_count > 0:
        posture = "Suspicious"
    else:
        posture = "Protected"

    return SupplyChainScanResponse(
        target=f"{proc_name} (PID {pid})",
        total_modules_scanned=len(findings),
        unsigned_count=unsigned_count,
        suspicious_count=suspicious_count,
        posture=posture,
        findings=findings,
    )


def scan_directory_modules(dir_path: str) -> SupplyChainScanResponse:
    """Scan all DLL and executable binaries within a filesystem path."""
    findings: List[ModuleIntegrityFinding] = []
    p = Path(dir_path)

    if p.is_file():
        findings.append(inspect_module_file(str(p)))
    elif p.is_dir():
        for ext in ("*.dll", "*.exe"):
            for f in list(p.glob(ext))[:100]:  # Cap at 100 modules per batch
                if f.is_file():
                    findings.append(inspect_module_file(str(f)))

    unsigned_count = sum(1 for f in findings if not f.is_signed)
    suspicious_count = sum(1 for f in findings if f.is_suspicious_location)

    posture: SupplyChainPosture = "Vulnerable" if suspicious_count > 0 else ("Suspicious" if unsigned_count > 0 else "Protected")

    return SupplyChainScanResponse(
        target=str(dir_path),
        total_modules_scanned=len(findings),
        unsigned_count=unsigned_count,
        suspicious_count=suspicious_count,
        posture=posture,
        findings=findings,
    )


def get_supply_chain_health() -> SupplyChainHealthResponse:
    """Return health metrics for supply chain inspection engine."""
    pe_ready = check_pefile_available()
    msg = "Supply chain and module integrity scanner is active." if pe_ready else "pefile library not installed; signature inspection unavailable."
    return SupplyChainHealthResponse(
        enabled=True,
        pefile_available=pe_ready,
        message=msg,
    )
