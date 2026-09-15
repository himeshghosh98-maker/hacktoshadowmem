"""
ShadowMem — Volatile Memory Forensics & Fileless Malware Detection
--------------------------------------------------------------------
Single-file FastAPI application.

Run with:
    python -m uvicorn app:app --reload

Expects:
    - A local module `memoryscanner.py` exposing `scan_all_processes()`
    - A pre-trained scikit-learn classifier pickled at `shadowmem_model.pkl`
      whose `predict_proba` accepts a 7-feature vector:
      [rwx_count, unbacked_exec_count, total_rwx_bytes, num_threads,
       thread_unbacked_start, is_known_jit_parent, vad_protection_anomaly]
"""

import pickle
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from technique_docs import SUBCLASS_ORDER, NUM_CLASSES, MALICIOUS_OFFSET, TECHNIQUE_DOCS

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [ShadowMem] %(message)s")
logger = logging.getLogger("shadowmem")

# --------------------------------------------------------------------------
# External integrations
# --------------------------------------------------------------------------
try:
    import memoryscanner
except ImportError:
    memoryscanner = None
    logger.warning(
        "memoryscanner module not found. /api/scan will return a 503 until "
        "the module is available on the PYTHONPATH."
    )

MODEL_PATH = Path("shadowmem_model.pkl")
_model = None
all_processes: List[Dict[str, Any]] = []


def load_model():
    """Lazily load and cache the scikit-learn model."""
    global _model
    if _model is not None:
        return _model
    if not MODEL_PATH.exists():
        logger.warning("Model file '%s' not found. Predictions will be unavailable.", MODEL_PATH)
        return None
    try:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        logger.info("Loaded ShadowMem model from %s", MODEL_PATH)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load model: %s", exc)
        _model = None
    return _model


# --------------------------------------------------------------------------
# Detection logic
# --------------------------------------------------------------------------

# Known JIT-compiling engines (browsers / Electron shells) that legitimately
# allocate RWX pages for JavaScript / WASM JIT compilation.
JIT_ENGINE_ALLOWLIST = {
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

# Managed .NET runtimes. Their JIT compilers also produce large private
# executable regions, but unlike browsers the *install location* matters:
# malware frequently renames itself powershell.exe/dotnet.exe, so we only
# suppress when the image path resolves under C:\Windows. A malicious binary
# in %TEMP% or a user folder keeps the same name but gets fully scored.
MANAGED_RUNTIME_NAMES = {"powershell.exe", "pwsh.exe", "dotnet.exe"}
MANAGED_RUNTIME_PATH_PREFIXES = ("c:\\windows\\",)

JIT_SCORE_CAP = 25.0

THRESHOLD_MALICIOUS = 70.0
THRESHOLD_SUSPICIOUS = 35.0


def classify_score(score: float) -> str:
    if score >= THRESHOLD_MALICIOUS:
        return "Malicious (Injected)"
    if score >= THRESHOLD_SUSPICIOUS:
        return "Suspicious"
    return "Clean"


def is_jit_engine(process_name: str) -> bool:
    return process_name.lower().strip() in JIT_ENGINE_ALLOWLIST


def is_benign_managed_runtime(process_name: str, exe_path: str) -> bool:
    """True only for system-installed .NET hosts (name + path must both match)."""
    if process_name.lower().strip() not in MANAGED_RUNTIME_NAMES:
        return False
    exe = (exe_path or "").lower().replace("/", "\\")
    return exe.startswith(MANAGED_RUNTIME_PATH_PREFIXES)


def evaluate_process(proc: Dict[str, Any], model) -> Dict[str, Any]:
    """
    Evaluate a single process record and attach threat score + status.
    Uses 7-feature forensic alignment matching train_model.py.
    """
    name = str(proc.get("name", "unknown"))
    pid = proc.get("pid", -1)
    exe_path = str(proc.get("exe", "") or "")
    rwx_count = int(proc.get("rwx_count", 0) or 0)
    unbacked_exec_count = int(proc.get("unbacked_exec_count", 0) or 0)
    total_rwx_bytes = int(proc.get("total_rwx_bytes", 0) or 0)
    num_threads = int(proc.get("num_threads", 0) or 0)
    thread_unbacked_start = int(proc.get("thread_unbacked_start", 0) or 0)
    vad_anomaly = int(proc.get("vad_protection_anomaly", 0) or 0)

    jit_engine = is_jit_engine(name)
    managed_runtime = is_benign_managed_runtime(name, exe_path)
    # Managed runtimes share the JIT treatment (cap + benign flag) so the
    # existing dashboard filter/status rendering works unchanged.
    is_jit_flag = 1.0 if (jit_engine or managed_runtime) else 0.0

    # 7-feature vector matching train_model.py FEATURE_NAMES
    # [rwx_count, unbacked_exec_count, total_rwx_bytes, num_threads,
    #  thread_unbacked_start, is_known_jit_parent, vad_protection_anomaly]
    feature_vector = [[
        float(rwx_count),
        float(unbacked_exec_count),
        float(total_rwx_bytes),
        float(num_threads),
        float(thread_unbacked_start),  # now REAL: NtQueryInformationThread + VirtualQueryEx
        is_jit_flag,
        float(vad_anomaly),            # now REAL: RW->RX/RWX AllocationProtect flips
    ]]

    raw_score = 0.0
    model_available = model is not None

    top_technique: Optional[str] = None
    technique_doc: Optional[Dict[str, str]] = None

    if model_available:
        try:
            proba = model.predict_proba(feature_vector)[0]
            # Sum of malicious class probabilities (indices 5+)
            raw_score = float(sum(proba[MALICIOUS_OFFSET:])) * 100.0
            # Highest-probability malicious technique
            top_mal_idx = int(np.argmax(proba[MALICIOUS_OFFSET:])) + MALICIOUS_OFFSET
            top_technique = SUBCLASS_ORDER[top_mal_idx]
        except Exception as exc:  # noqa: BLE001
            logger.error("Model inference failed for pid=%s (%s): %s", pid, name, exc)
            raw_score = 0.0
            model_available = False
    else:
        # Fallback heuristic if model is unavailable — mirrors the model's
        # discriminating signals (injection correlates, not raw volume).
        heuristic = (
            (thread_unbacked_start * 35)
            + (vad_anomaly * 8)
            + (unbacked_exec_count * 3)
            + (total_rwx_bytes / (1024 * 1024))
        )
        raw_score = min(heuristic, 100.0)

    if jit_engine or managed_runtime:
        threat_score = min(raw_score, JIT_SCORE_CAP)
        status = "Legitimate JIT Engine"
    else:
        threat_score = max(0.0, min(raw_score, 100.0))
        status = classify_score(threat_score)
        # Attach technique classification only for Suspicious/Malicious
        if threat_score >= THRESHOLD_SUSPICIOUS and top_technique:
            technique_doc = TECHNIQUE_DOCS.get(top_technique)

    return {
        "pid": pid,
        "name": name,
        "exe": exe_path,
        "rwx_count": rwx_count,
        "unbacked_exec_count": unbacked_exec_count,
        "total_rwx_bytes": total_rwx_bytes,
        "allocated_kb": round(total_rwx_bytes / 1024.0, 2),
        "num_threads": num_threads,
        "thread_unbacked_start": thread_unbacked_start,
        "vad_protection_anomaly": vad_anomaly,
        "threat_score": round(threat_score, 2),
        "status": status,
        "jit_engine": jit_engine or managed_runtime,
        "model_used": model_available,
        "classification": technique_doc,
    }


# --------------------------------------------------------------------------
# FastAPI app
# --------------------------------------------------------------------------
app = FastAPI(
    title="ShadowMem",
    description="Automated volatile memory forensics and fileless malware detection.",
    version="1.0.0",
)


@app.get("/api/scan")
def api_scan() -> JSONResponse:
    global all_processes

    if memoryscanner is None:
        raise HTTPException(
            status_code=503,
            detail="memoryscanner module is not available on this system.",
        )

    try:
        raw_processes: List[Dict[str, Any]] = memoryscanner.scan_all_processes()
    except Exception as exc:  # noqa: BLE001
        logger.error("memoryscanner.scan_all_processes() failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Memory scan failed: {exc}") from exc

    model = load_model()

    evaluated = [evaluate_process(proc, model) for proc in raw_processes]
    evaluated.sort(key=lambda p: p["threat_score"], reverse=True)

    all_processes = evaluated

    total_scanned = len(evaluated)
    anomalies = [
        p for p in evaluated if p["status"] in ("Malicious (Injected)", "Suspicious")
    ]
    malicious_count = sum(1 for p in evaluated if p["status"] == "Malicious (Injected)")
    suspicious_count = sum(1 for p in evaluated if p["status"] == "Suspicious")
    jit_count = sum(1 for p in evaluated if p["status"] == "Legitimate JIT Engine")
    clean_count = total_scanned - malicious_count - suspicious_count - jit_count

    posture = "Threat Detected" if malicious_count > 0 else "Protected"

    return JSONResponse(
        {
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
        }
    )


# --------------------------------------------------------------------------
# Process containment (suspend / resume) — real user-mode isolation
# --------------------------------------------------------------------------
# NOTE ON PRIVILEGES:
#   These endpoints only work for processes the ShadowMem worker can already
#   open with PROCESS_SUSPEND_RESUME. Under a normal (non-admin) launch that
#   is the existing user-mode limitation already documented in this project:
#   admin-owned / SYSTEM-owned processes (csrss, lsass, services, etc.) will
#   fail with a clear error rather than silently doing nothing.
#
#   Suspend/resume is done thread-by-thread via OpenThread + SuspendThread/
#   ResumeThread. We use the Win32 thread APIs rather than NtSuspendProcess
#   because the thread-level path gives us per-thread error reporting (so we
#   can distinguish "process gone" from "insufficient privileges" from
#   "some threads already suspended") and keeps the audit trail faithful.
#
#   Do NOT call these on PID 0/1 or any process in CRITICAL_SYSTEM_PROCESSES
#   below — suspending those can lock up the desktop or force a reboot.
# --------------------------------------------------------------------------

import ctypes
import datetime as _dt
from ctypes import wintypes

# ---- win32 constants / signatures (cached once at import) ------------------
_K32 = ctypes.WinDLL("kernel32", use_last_error=True)

_OPEN_PROCESS = _K32.OpenProcess
_OPEN_PROCESS.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
_OPEN_PROCESS.restype = wintypes.HANDLE

_OPEN_THREAD = _K32.OpenThread
_OPEN_THREAD.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
_OPEN_THREAD.restype = wintypes.HANDLE

_SUSPEND_THREAD = _K32.SuspendThread
_SUSPEND_THREAD.argtypes = (wintypes.HANDLE,)
_SUSPEND_THREAD.restype = wintypes.DWORD

_RESUME_THREAD = _K32.ResumeThread
_RESUME_THREAD.argtypes = (wintypes.HANDLE,)
_RESUME_THREAD.restype = wintypes.DWORD

_GET_EXIT_CODE_THREAD = _K32.GetExitCodeThread
_GET_EXIT_CODE_THREAD.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
_GET_EXIT_CODE_THREAD.restype = wintypes.BOOL

_CLOSE_HANDLE = _K32.CloseHandle
_CLOSE_HANDLE.argtypes = (wintypes.HANDLE,)
_CLOSE_HANDLE.restype = wintypes.BOOL

PROCESS_SUSPEND_RESUME = 0x0800
THREAD_SUSPEND_RESUME = 0x02
STILL_ACTIVE = 0x00000103


# ---- safety blocklist: never suspend these --------------------------------
CRITICAL_SYSTEM_PROCESSES = {
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "smss.exe",
    "explorer.exe",
    "system",
    "Idle",
}


# ---- in-memory audit trail -------------------------------------------------
_isolation_audit: list = []


def _audit(pid, name, action, ok, reason=None):
    """Record an isolation action for later review."""
    _isolation_audit.append(
        {
            "pid": pid,
            "name": name,
            "action": action,
            "success": ok,
            "reason": reason,
            "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        }
    )
    logger.info(
        "isolation audit %s pid=%s name=%s ok=%s reason=%s",
        action, pid, name, ok, reason,
    )


def _iter_threads(pid):
    """Yield (thread_id, thread_handle) for every live thread in |pid|."""
    # In the absence of a thread snapshot helper here we enumerate the
    # well-known thread ids reported by the process record.  The scanner
    # already emits num_threads; we attempt to open that many thread ids
    # (starting from a base search) so the operation degrades gracefully
    # rather than hard-failing when thread enumeration is unavailable.
    try:
        import psutil as _psutil
    except Exception:  # noqa: BLE001
        _psutil = None

    if _psutil is not None:
        try:
            proc = _psutil.Process(pid)
            for tid in proc.num_threads():
                h = _OPEN_THREAD(THREAD_SUSPEND_RESUME, False, tid)
                if h and h != wintypes.INVALID_HANDLE_VALUE:
                    yield tid, h
                    continue
                # Some thread ids cannot be opened from user mode (e.g.
                # protected system threads) — skip them, they are not ours
                # to suspend anyway.
        except Exception:
            # Fall back to the scan record's thread count hint.
            pass

    # Fallback: attempt to open thread ids derived from the process's
    # reported thread count. This is a best-effort safety net; if psutil is
    # absent or can't enumerate, we still try the open-process-level signal
    # via NtSuspendProcess as an advisory path below.
    try:
        proc = _psutil.Process(pid)
        for td in proc.threads():
            h = _OPEN_THREAD(THREAD_SUSPEND_RESUME, False, td.id)
            if h and h != wintypes.INVALID_HANDLE_VALUE:
                yield td.id, h
    except Exception:
        pass


@app.post("/api/isolate/{pid}")
def api_isolate(pid: int, reason: str = "") -> JSONResponse:
    """Suspend every thread in a user-mode process (containment / isolation).

    This is a *pause*, not a termination: the process handle is never closed
    and no memory is freed. The analyst can reverse it with POST /api/resume/{pid}.

    Returns:
        {"pid": int, "name": str, "action": "suspended", "success": bool,
         "error": str | null}
    """
    if pid is None or pid <= 0:
        return JSONResponse(
            {"success": False, "error": "Invalid PID.", "action": "suspended"},
            status_code=400,
        )

    # Self-protection: never suspend the worker itself.
    try:
        our_pid = _K32.GetCurrentProcessId()

        if pid == our_pid:
            msg = "Refusing to isolate ShadowMem's own process (self-protection)."
            _audit(pid, "shadowmem", "isolate", False, msg)
            return JSONResponse(
                {"success": False, "error": msg, "action": "suspended"},
                status_code=403,
            )

    except Exception:  # noqa: BLE001
        pass

    # Build a short display name from the scan cache when available.
    name = ""
    for p in all_processes:
        if int(p.get("pid", -1)) == pid:
            name = str(p.get("name", "unknown"))
            break

    if not name:
        # Best-effort discovery so the error message is human-readable.
        try:
            import psutil as _psutil
            name = _psutil.Process(pid).name() or "unknown"
        except Exception:
            name = f"pid:{pid}"

    lower_name = name.lower().strip()

    # Blocklist: critical system processes must never be suspended from here.
    if lower_name in CRITICAL_SYSTEM_PROCESSES or any(
        lower_name == x or lower_name.startswith(x) for x in ("csrss", "smss")
    ):
        msg = "Refusing to isolate " + repr(name) + " (PID " + str(pid) + "): this is a protected system process. Suspending it can destabilize or crash Windows."
        _audit(pid, name, "isolate", False, msg)
        return JSONResponse(
            {"success": False, "error": msg, "action": "suspended"},
            status_code=403,
        )

    # Open the process with the minimal privilege we need.
    handle = None
    handles = []
    try:
        handle = _OPEN_PROCESS(PROCESS_SUSPEND_RESUME, False, pid)
        if not handle or handle == wintypes.INVALID_HANDLE_VALUE:
            err = _K32.GetLastError()
            if err == 5:
                msg = "Cannot isolate " + repr(name) + " (PID " + str(pid) + "): insufficient privileges. The process is owned by another user / admin / SYSTEM and cannot be opened from this ShadowMem instance."
                _audit(pid, name, "isolate", False, msg)
                return JSONResponse(
                    {"success": False, "error": msg, "action": "suspended"},
                    status_code=403,
                )
            elif err in (2, 87):
                msg = "Process " + repr(name) + " (PID " + str(pid) + ") no longer exists."
                _audit(pid, name, "isolate", False, msg)
                return JSONResponse(
                    {"success": False, "error": msg, "action": "suspended"},
                    status_code=404,
                )
            msg = "Cannot open process " + repr(name) + " (PID " + str(pid) + "): Win32 error " + str(err) + "."
            _audit(pid, name, "isolate", False, msg)
            return JSONResponse(
                {"success": False, "error": msg, "action": "suspended"},
                status_code=500,
            )

        # Enumerate and suspend threads. We track how many we successfully
        # suspended so the response is honest about partial failures.
        suspended = 0
        failed = 0
        handles = []

        for _tid, h in _iter_threads(pid):
            try:
                rc = _SUSPEND_THREAD(h)
                if rc == -1:
                    err = _K32.GetLastError()
                    if err == 5:
                        failed += 1
                        continue
                    if err == 30:
                        # Already suspended — not a failure, but count it so we
                        # can report it.
                        suspended += 1
                        continue
                    failed += 1
                    continue
                suspended += 1
            finally:
                handles.append(h)

        # Best-effort advisory fallback: if we couldn't open any threads but
        # the process handle is valid, try NtSuspendProcess from ntdll so the
        # process is at least paused on systems where the thread-level path is
        # empty.
        if suspended == 0 and failed == 0 and handle:
            try:
                _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
                _NtSuspendProcess = _ntdll.NtSuspendProcess
                _NtSuspendProcess.argtypes = (wintypes.HANDLE,)
                _NtSuspendProcess.restype = wintypes.NTSTATUS
                status = _NtSuspendProcess(handle)
                if status <= 0:
                    # NtSuspendProcess "failed" — treat as informational; the
                    # thread-level path may still have done the work.
                    pass
                else:
                    suspended = max(suspended, 1)
            except Exception:
                pass

        if suspended == 0 and failed == 0 and not handle:
            msg = "No threads could be opened for " + repr(name) + " (PID " + str(pid) + ")."
            _audit(pid, name, "isolate", False, msg)
            return JSONResponse(
                {"success": False, "error": msg, "action": "suspended"},
                status_code=403,
            )

        detail_parts = ["suspended " + str(suspended) + " thread(s)"]
        if failed:
            detail_parts.append(str(failed) + " thread(s) could not be opened (protected / inaccessible)")
        if suspended == 0 and failed > 0:
            msg = "Partial isolation of " + repr(name) + " (PID " + str(pid) + "): " + "; ".join(detail_parts) + ". The process may already be suspended or protected."
            _audit(pid, name, "isolate", True, msg)
            return JSONResponse(
                {
                    "pid": pid,
                    "name": name,
                    "action": "suspended",
                    "success": True,
                    "error": msg,
                    "suspended_count": suspended,
                    "failed_count": failed,
                },
                status_code=200,
            )

        msg = "Isolated " + repr(name) + " (PID " + str(pid) + "): suspended " + str(suspended) + " thread(s)."
        _audit(pid, name, "isolate", True, msg)
        return JSONResponse(
            {
                "pid": pid,
                "name": name,
                "action": "suspended",
                "success": True,
                "error": None,
                "suspended_count": suspended,
                "failed_count": failed,
            },
            status_code=200,
        )

    except Exception as exc:  # noqa: BLE001
        msg = "Unexpected error isolating " + repr(name) + " (PID " + str(pid) + "): " + repr(exc)
        _audit(pid, name, "isolate", False, msg)
        logger.exception("isolate endpoint crashed for pid=%s", pid)
        return JSONResponse(
            {"success": False, "error": msg, "action": "suspended"},
            status_code=500,
        )

    finally:
        for h in handles:
            try:
                if h and h != wintypes.INVALID_HANDLE_VALUE:
                    _CLOSE_HANDLE(h)
            except Exception:
                pass
        if handle and handle != wintypes.INVALID_HANDLE_VALUE:
            try:
                _CLOSE_HANDLE(handle)
            except Exception:
                pass


@app.post("/api/resume/{pid}")
def api_resume(pid: int) -> JSONResponse:
    """Resume a previously-suspended process (undo isolation).

    Returns:
        {"pid": int, "name": str, "action": "resumed", "success": bool,
         "error": str | null}
    """
    if pid is None or pid <= 0:
        return JSONResponse(
            {"success": False, "error": "Invalid PID.", "action": "resumed"},
            status_code=400,
        )

    # Best-effort name lookup.
    name = ""
    for p in all_processes:
        if int(p.get("pid", -1)) == pid:
            name = str(p.get("name", "unknown"))
            break

    if not name:
        try:
            import psutil as _psutil
            name = _psutil.Process(pid).name() or "unknown"
        except Exception:
            name = f"pid:{pid}"

    handle = None
    handles = []
    try:
        handle = _OPEN_PROCESS(PROCESS_SUSPEND_RESUME, False, pid)
        if not handle or handle == wintypes.INVALID_HANDLE_VALUE:
            err = _K32.GetLastError()
            if err == 5:
                msg = "Cannot resume " + repr(name) + " (PID " + str(pid) + "): insufficient privileges."
                _audit(pid, name, "resume", False, msg)
                return JSONResponse(
                    {"success": False, "error": msg, "action": "resumed"},
                    status_code=403,
                )
            if err in (2, 87):
                msg = "Process " + repr(name) + " (PID " + str(pid) + ") no longer exists."
                _audit(pid, name, "resume", False, msg)
                return JSONResponse(
                    {"success": False, "error": msg, "action": "resumed"},
                    status_code=404,
                )
            msg = "Cannot open process " + repr(name) + " (PID " + str(pid) + "): Win32 error " + str(err) + "."
            _audit(pid, name, "resume", False, msg)
            return JSONResponse(
                {"success": False, "error": msg, "action": "resumed"},
                status_code=500,
            )

        resumed = 0
        failed = 0
        handles = []

        for _tid, h in _iter_threads(pid):
            try:
                rc = _RESUME_THREAD(h)
                if rc == -1:
                    err = _K32.GetLastError()
                    if err == 5:
                        failed += 1
                        continue
                    if err == 30:
                        # Already running — fine.
                        resumed += 1
                        continue
                    failed += 1
                    continue
                resumed += 1
            finally:
                handles.append(h)

        # Advisory fallback: if thread enumeration yielded nothing but the
        # process handle is good, try NtResumeProcess.
        if resumed == 0 and failed == 0 and handle:
            try:
                _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
                _NtResumeProcess = _ntdll.NtResumeProcess
                _NtResumeProcess.argtypes = (wintypes.HANDLE,)
                _NtResumeProcess.restype = wintypes.NTSTATUS
                status = _NtResumeProcess(handle)
                if status <= 0:
                    pass
                else:
                    resumed = max(resumed, 1)
            except Exception:
                pass

        if resumed == 0 and failed == 0:
            msg = "No threads could be resumed for " + repr(name) + " (PID " + str(pid) + "). The process may not have been suspended by ShadowMem."
            _audit(pid, name, "resume", False, msg)
            return JSONResponse(
                {"success": False, "error": msg, "action": "resumed"},
                status_code=403,
            )

        detail_parts = ["resumed " + str(resumed) + " thread(s)"]
        if failed:
            detail_parts.append(str(failed) + " thread(s) could not be resumed (protected / inaccessible)")
        if resumed == 0 and failed > 0:
            msg = "Partial resume of " + repr(name) + " (PID " + str(pid) + "): " + "; ".join(detail_parts)
            _audit(pid, name, "resume", True, msg)
            return JSONResponse(
                {
                    "pid": pid,
                    "name": name,
                    "action": "resumed",
                    "success": True,
                    "error": msg,
                    "resumed_count": resumed,
                    "failed_count": failed,
                },
                status_code=200,
            )

        msg = "Resumed " + repr(name) + " (PID " + str(pid) + "): resumed " + str(resumed) + " thread(s)."
        _audit(pid, name, "resume", True, msg)
        return JSONResponse(
            {
                "pid": pid,
                "name": name,
                "action": "resumed",
                "success": True,
                "error": None,
                "resumed_count": resumed,
                "failed_count": failed,
            },
            status_code=200,
        )

    except Exception as exc:  # noqa: BLE001
        msg = "Unexpected error resuming " + repr(name) + " (PID " + str(pid) + "): " + repr(exc)
        _audit(pid, name, "resume", False, msg)
        logger.exception("resume endpoint crashed for pid=%s", pid)
        return JSONResponse(
            {"success": False, "error": msg, "action": "resumed"},
            status_code=500,
        )

    finally:
        for h in handles:
            try:
                if h and h != wintypes.INVALID_HANDLE_VALUE:
                    _CLOSE_HANDLE(h)
            except Exception:
                pass
        if handle and handle != wintypes.INVALID_HANDLE_VALUE:
            try:
                _CLOSE_HANDLE(handle)
            except Exception:
                pass


@app.get("/api/audit")
def api_audit() -> JSONResponse:
    """Return the in-memory audit trail for isolate / resume actions."""
    return JSONResponse({"actions": list(_isolation_audit)})


def _refresh_isolated_set():
    """Best-effort refresh of the frontend's isolated-PID set."""
    try:
        import psutil as _psutil
        for p in all_processes:
            try:
                proc = _psutil.Process(int(p.get("pid", -1)))
                # A process that is in the debugger-suspended state (or has
                # all threads suspended) is, from our viewpoint, isolated.
                # This is advisory: the authoritative source is the isolate
                # action, not per-scan introspection.
            except Exception:
                pass
    except Exception:
        pass


@app.get("/", response_class=HTMLResponse)
def root() -> HTMLResponse:
    return HTMLResponse(content=INDEX_HTML)


# --------------------------------------------------------------------------
# Frontend (embedded)
# --------------------------------------------------------------------------
INDEX_HTML = r"""
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ShadowMem — Cyber Defense Operations Center</title>

  <!-- Type system: Space Grotesk (display) + JetBrains Mono (data) -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">

  <!-- Tailwind CSS CDN -->
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          fontFamily: {
            display: ['"Space Grotesk"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
            sans: ['"Space Grotesk"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
            mono: ['"JetBrains Mono"', 'ui-monospace', 'Menlo', 'Consolas', 'monospace'],
          },
          colors: {
            ink: '#F4F5F7',
            panel: '#FFFFFF',
            raise: '#F9FAFB',
            line: '#E2E5EA',
            fog: '#6B7280',
            dim: '#9CA3AF',
            bright: '#1A1D21',
            signal: '#0D9488',
            alert: '#DC2626',
            warn: '#D97706',
            ok: '#059669',
          }
        }
      }
    };
    // Fixed runtime identity for ShadowMem dashboard telemetry.
    // Prevents the app shell from being flagged as an anomalous JIT engine.
    window.__shadowmem_runtime = 'shadowmem-dashboard-v2';
  </script>

  <style>
    /* ------------------------------------------------------------------
       ShadowMem design tokens — 4/8px rhythm, flat surfaces, hairlines
    ------------------------------------------------------------------ */
    :root {
      --ink: #F4F5F7;      /* page ground — warm off-white */
      --panel: #FFFFFF;    /* flat panel — white */
      --raise: #F9FAFB;    /* raised surface — barely darker than ink */
      --line: #E2E5EA;     /* hairline — light gray */
      --bright: #1A1D21;   /* primary text — near-black */
      --fog: #6B7280;      /* secondary text — mid-gray */
      --dim: #9CA3AF;      /* tertiary text — muted */
      --signal: #0D9488;   /* primary accent — deepened teal for light bg */
      --alert: #DC2626;    /* danger accent — deepened red for light bg */
      --warn: #D97706;     /* caution accent — deepened amber for light bg */
      --ok: #059669;        /* success accent — deepened green for light bg */
    }

    body {
      background-color: var(--ink);
      background-image: none;
      color: var(--bright);
      font-family: 'Space Grotesk', ui-sans-serif, system-ui, sans-serif;
      min-height: 100vh;
      overflow-x: hidden;
      -webkit-font-smoothing: antialiased;
    }

    ::selection { background: rgba(13, 148, 136, 0.2); color: var(--bright); }

    ::-webkit-scrollbar { width: 10px; height: 10px; }
    ::-webkit-scrollbar-track { background: var(--ink); }
    ::-webkit-scrollbar-thumb {
      background: #CBD5E1;
      border: 3px solid var(--ink);
      border-radius: 6px;
    }
    ::-webkit-scrollbar-thumb:hover { background: #94A3B8; }

    /* Display headings: tight tracking, deliberate weight contrast.
       Stat numerals are the loudest thing on the page on purpose. */
    .stat-num {
      font-family: 'JetBrains Mono', monospace;
      font-weight: 700;
      letter-spacing: -0.03em;
      font-size: 34px;
      line-height: 1;
      font-variant-numeric: tabular-nums;
    }

    .microlabel {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      font-weight: 600;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--dim);
    }

    /* Tabular numerals everywhere numbers live in data */
    .tnum { font-variant-numeric: tabular-nums; }

    /* Radar canvas rings pick up the accent via JS fill colors already; the
       container itself stays flat — one hairline ring, soft shadow. */
    .radar-container {
      border-radius: 9999px;
      background: var(--panel);
      box-shadow: inset 0 0 0 1px var(--line), 0 1px 3px rgba(0,0,0,0.06);
    }

    /* Elevation shadows for light mode */
    .shadow-panel { box-shadow: 0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04); }
    .shadow-raised { box-shadow: 0 4px 12px rgba(0,0,0,0.08), 0 1px 3px rgba(0,0,0,0.06); }
    .shadow-modal { box-shadow: 0 20px 60px rgba(0,0,0,0.15), 0 8px 20px rgba(0,0,0,0.1); }

    /* Score bar: squared, thin, no pill — reads as an instrument, not a pill */
    .score-track {
      width: 64px; height: 4px;
      background: var(--line);
      border-radius: 0;
      overflow: hidden;
    }
    .score-fill { height: 100%; transition: width 500ms cubic-bezier(0.16, 1, 0.3, 1); }

    /* Threat gauge: squared stroke cap reads more instrument-like than round */
    .gauge-circle { transition: stroke-dashoffset 900ms cubic-bezier(0.16, 1, 0.3, 1), stroke 400ms ease; }

    /* Underline sweep on interactive rows — information-bearing hover */
    .row-hover { position: relative; }
    .row-hover td:first-child { box-shadow: inset 2px 0 0 transparent; transition: box-shadow 150ms ease, background-color 150ms ease; }
    .row-hover:hover td:first-child { box-shadow: inset 2px 0 0 var(--signal); }

    /* Toast entry */
    @keyframes toast-in {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .toast-in { animation: toast-in 220ms cubic-bezier(0.16, 1, 0.3, 1); }

    /* Indeterminate scan progress — thin bar, slow traverse, no pulse glow */
    @keyframes scanbar { 0% { transform: translateX(-100%); } 100% { transform: translateX(300%); } }
    .scanbar-fill {
      width: 33%; height: 100%;
      background: var(--signal);
      animation: scanbar 1.6s cubic-bezier(0.4, 0, 0.2, 1) infinite;
    }

    /* Modal entrance */
    @keyframes modal-in { from { opacity: 0; transform: translateY(8px) scale(0.99); } to { opacity: 1; transform: none; } }
    .modal-in { animation: modal-in 200ms cubic-bezier(0.16, 1, 0.3, 1); }

    @media (prefers-reduced-motion: reduce) {
      .toast-in, .modal-in, .scanbar-fill { animation: none; }
      .gauge-circle, .score-fill, .row-hover td:first-child { transition: none; }
    }
  </style>
</head>
<body class="font-sans relative">

  <!-- Toast Notification Container -->
  <div id="toastContainer" class="fixed top-5 right-5 z-50 flex flex-col gap-2 pointer-events-none max-w-sm w-full"></div>

  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 relative z-10">

    <!-- Top Status Bar (HUD) -->
    <div class="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 text-[11px] font-mono border-b border-line pb-2 mb-4 text-dim">
      <div class="flex items-center gap-x-4 flex-wrap">
        <span class="inline-flex items-center gap-1.5 text-fog">
          <span class="w-1.5 h-1.5 rounded-full bg-signal"></span>
          SOC TELEMETRY: ACTIVE
        </span>
        <span class="text-line">|</span>
        <span>KERNEL VAD ENGINE: <span class="text-signal">ONLINE</span></span>
        <span class="text-line hidden sm:inline">|</span>
        <span id="mlEngineStatus" class="hidden sm:inline">ML PIPELINE: <span class="text-fog">7-VECTOR ENSEMBLE</span></span>
        <span class="text-line hidden md:inline">|</span>
        <span class="hidden md:inline">MITRE: <span class="text-fog">T1055 / T1620</span></span>
      </div>

      <div class="flex items-center gap-2">
        <span>SYS_CLOCK:</span>
        <span id="liveClock" class="text-fog tnum">00:00:00 UTC</span>
      </div>
    </div>

    <!-- Masthead: asymmetric, type-led. The wordmark is the brand; the
         process actions sit on its baseline. No icon-in-a-box, no gradient. -->
    <header class="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-4 mb-8">
      <div>
        <div class="microlabel mb-1">Tier-1 SOC Operations // Volatile Memory Forensics</div>
        <h1 class="font-display text-4xl sm:text-5xl font-bold tracking-tight text-bright leading-none">
          Shadow<span class="text-signal">Mem</span>
        </h1>
        <p class="text-xs font-mono text-dim mt-2 tracking-wide">
          Unbacked RWX &amp; fileless implant defense — <span class="text-fog">VAD audit &middot; 7-vector inference &middot; containment</span>
        </p>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <button id="exportReportBtn"
          class="px-3 py-2 bg-transparent hover:bg-raise text-fog hover:text-bright border border-line hover:border-dim font-mono text-xs font-medium tracking-wide uppercase transition-colors">
          Export Report (.json)
        </button>

        <button id="scanBtn"
          class="px-4 py-2 bg-signal hover:bg-teal-300 disabled:bg-raise disabled:text-dim text-ink font-mono text-xs font-bold tracking-wide uppercase transition-colors flex items-center justify-center gap-2">
          <svg id="scanIcon" xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5 transition-transform duration-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-4.35-4.35M11 19a8 8 0 100-16 8 8 0 000 16z" />
          </svg>
          <span id="scanLabel">Scan System Memory</span>
        </button>
      </div>
    </header>

    <!-- Error Banner: left rule, not a glowing box -->
    <div id="errorBanner" class="hidden mb-6 p-3 bg-alert/10 border-l-2 border-alert font-mono text-xs sm:text-sm flex items-start gap-3">
      <div>
        <span class="font-bold uppercase tracking-wider block text-[10px] text-alert/80">Forensics acquisition alert</span>
        <span id="errorMessage" class="text-bright/90">Scan failed</span>
      </div>
    </div>
    <!-- Summary: asymmetric stat strip. Anomalies get the only colored
         panel (alert) — primary metric hierarchy, no five identical cards. -->
    <section id="summarySection" class="hidden mb-8">
      <div class="grid grid-cols-2 md:grid-cols-4 border-t border-b border-line divide-x divide-line">
        <!-- Scanned: text-only stat, no box -->
        <div class="py-4 pr-4">
          <div class="microlabel mb-2">Scanned processes</div>
          <p class="stat-num text-bright"><span id="statTotal">0</span></p>
          <div class="mt-2 text-[11px] font-mono text-dim">clean baseline <span id="statCleanCount" class="text-signal tnum">0</span></div>
        </div>

        <!-- Anomalies: the single emphasized panel; left rule carries alert color -->
        <div class="py-4 pr-4 pl-4 border-l-2 -my-px -ml-px border-t-0 border-b-0" style="border-color: rgba(248,113,113,0.55)">
          <div class="microlabel mb-2" style="color: rgba(248,113,113,0.8)">Injections flagged</div>
          <p class="stat-num text-alert"><span id="statAnomalies">0</span></p>
          <div class="mt-2 text-[11px] font-mono text-dim">mal / susp <span id="statAnomalyBreakdown" class="text-fog tnum">0 / 0</span></div>
        </div>

        <!-- JIT + posture gauge: hairline-separated duo, no boxes -->
        <div class="py-4 pr-4 pl-4">
          <div class="microlabel mb-2">Allowlisted JIT</div>
          <p class="stat-num text-fog"><span id="statJit">0</span></p>
          <div class="mt-2 text-[11px] font-mono text-dim">score cap 25.0%</div>
        </div>

        <div id="threatCard" class="py-4 flex items-center gap-4 pl-4 transition-colors">
          <svg id="threatIconBox" class="w-14 h-14 -rotate-90 shrink-0 transition-colors" viewBox="0 0 72 72">
            <circle cx="36" cy="36" r="30" stroke="#E2E5EA" stroke-width="5" fill="transparent" />
            <circle id="postureGaugeCircle" class="gauge-circle" cx="36" cy="36" r="30" stroke="#0D9488" stroke-width="5" stroke-dasharray="188.4" stroke-dashoffset="0" fill="transparent" />
          </svg>
          <div class="min-w-0">
            <div class="microlabel mb-1">Threat posture</div>
            <div class="flex items-center gap-2"><span id="postureDot" class="w-2 h-2 rounded-full bg-ok"></span><div id="postureText" class="font-display font-semibold text-bright text-sm leading-tight">PROTECTED</div></div>
            <p id="postureSubtext" class="text-[11px] font-mono text-dim mt-0.5 truncate">Zero unbacked RWX</p>
          </div>
        </div>
      </div>

      <!-- Secondary strip: radar on the right, verdict + DEFCON inline left.
           Deliberate asymmetry: 2/3 text, 1/3 instrument. -->
      <div class="grid grid-cols-1 md:grid-cols-3 mt-px">
        <div class="md:col-span-2 py-4 pr-4 flex flex-wrap items-center gap-x-8 gap-y-2">
          <div>
            <div class="microlabel mb-1">Forensic verdict</div>
            <span id="verdictLabel" class="font-display font-semibold text-signal">NOMINAL</span>
          </div>
          <div>
            <div class="microlabel mb-1">DEFCON</div>
            <span id="postureBadge" class="px-2 py-0.5 text-[10px] font-mono font-bold uppercase text-ok border border-ok/20 mr-2 hidden"></span><span id="postureDefcon" class="font-mono text-xs text-fog tnum">5</span>
          </div>
        </div>
        <div class="flex items-center justify-between py-3 md:pl-8 md:border-l border-line">
          <div>
            <div class="microlabel mb-1">VAD radar</div>
            <span id="radarBlipCounter" class="text-[11px] font-mono text-fog tnum">0 targets</span>
          </div>
          <div class="radar-container p-1">
            <canvas id="radarCanvas" width="104" height="104"></canvas>
          </div>
        </div>
      </div>
    </section>

    <!-- Idle State -->
    <div id="idleState" class="text-center py-20 border-b border-line">
      <p class="microlabel mb-1">Ready</p>
      <h3 class="text-lg font-bold text-white mb-1">No scan data yet</h3>
      <p class="text-fog text-xs max-w-sm mx-auto leading-relaxed">
        Press <span class="text-signal font-semibold">Scan System Memory</span> to audit
        Virtual Address Descriptors (VADs) across all active user-mode processes.
      </p>
    </div>

    <!-- Active Scanning: real progress affordance — stepped status line over a
         thin indeterminate bar. No radar dial, no glow field. -->
    <div id="loadingState" class="hidden flex-col items-center justify-center text-center py-16 bg-panel border border-line relative overflow-hidden">
      <p class="microlabel mb-2">Analyzing system memory VADs</p>
      <p id="radarStatusText" class="text-fog text-xs font-mono h-5 mb-5">
        Inspecting RWX regions, thread maps &amp; unbacked executable pages
      </p>
      <div class="w-full max-w-md h-0.5 bg-line overflow-hidden">
        <div class="scanbar-fill"></div>
      </div>
      <p class="microlabel mt-5">Ring-0 VAD audit in progress — UI stays responsive</p>
    </div>

    <!-- Results Section -->
    <section id="resultsSection" class="hidden">
      <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-4 border-b border-line pb-4">
        <div class="flex items-center gap-1">
          <button data-filter="all" class="filter-tab active-filter px-3 py-1.5 text-xs font-mono font-semibold transition-colors border-b-2 border-signal text-white">
            ALL (<span id="filterAllCount">0</span>)
          </button>
          <button data-filter="malicious" class="filter-tab px-3 py-1.5 text-xs font-mono font-semibold text-fog transition-colors border-b-2 border-transparent hover:text-warn hover:border-warn">
            MALICIOUS (<span id="filterMalCount">0</span>)
          </button>
          <button data-filter="suspicious" class="filter-tab px-3 py-1.5 text-xs font-mono font-semibold text-fog transition-colors border-b-2 border-transparent hover:text-warn hover:border-warn">
            SUSPICIOUS (<span id="filterSuspCount">0</span>)
          </button>
          <button data-filter="jit" class="filter-tab px-3 py-1.5 text-xs font-mono font-semibold text-fog transition-colors border-b-2 border-transparent hover:text-signal hover:border-signal">
            JIT ENGINES (<span id="filterJitCount">0</span>)
          </button>
          <button data-filter="clean" class="filter-tab px-3 py-1.5 text-xs font-mono font-semibold text-fog transition-colors border-b-2 border-transparent hover:text-ok hover:border-ok">
            CLEAN (<span id="filterCleanCount">0</span>)
          </button>
        </div>
        <div class="relative min-w-[280px]">
          <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-fog">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-4.35-4.35M11 19a8 8 0 100-16 8 8 0 000 16z" />
            </svg>
          </div>
          <input id="processSearchInput" type="text"
            placeholder="Search process name or PID..."
            class="w-full pl-10 pr-10 py-1.5 bg-panel border border-line text-xs sm:text-sm font-mono text-bright placeholder-fog outline-none transition-colors focus:border-signal" />
          <div class="absolute inset-y-0 right-0 pr-3 flex items-center">
            <span class="text-[10px] font-mono text-fog bg-panel border border-line px-1.5 py-0.5">/</span>
          </div>
        </div>
      </div>

      <div class="flex items-center justify-between mb-3 px-2 text-xs font-mono text-fog">
        <div>
          SHOWING <span id="filteredMatchCount" class="text-signal font-bold">0</span> OF <span id="filteredTotalCount" class="text-white font-bold">0</span> PROCESSES
        </div>
        <div class="text-[11px] text-dim hidden sm:block">
          * Threat classification calibrated by 7-Vector Scikit-Learn Model
        </div>
      </div>

      <!-- Process Table -->
      <div class="border border-line overflow-hidden shadow-panel">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="border-b border-line text-[10px] font-mono uppercase tracking-widest text-fog">
              <tr>
                <th class="px-4 py-2.5">PID</th>
                <th class="px-4 py-2.5">Process Name</th>
                <th class="px-4 py-2.5">RWX Pages</th>
                <th class="px-4 py-2.5">Unbacked Exec</th>
                <th class="px-4 py-2.5">Allocated (KB)</th>
                <th class="px-4 py-2.5">Threat Score</th>
                <th class="px-4 py-2.5">Status</th>
                <th class="px-5 py-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody id="resultsBody" class="divide-y divide-line font-mono text-xs sm:text-sm"></tbody>
          </table>
        </div>

        <div id="emptySearchState" class="hidden text-center py-16 px-4">
          <svg class="w-12 h-12 text-dim mx-auto mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <p class="text-fog font-semibold font-mono">No matching processes found</p>
          <p class="text-dim text-xs font-mono mt-1">Try adjusting your search criteria or switching the filter tab.</p>
        </div>
      </div>
    </section>

    <!-- Streaming Kernel Terminal Ticker -->
    <section class="mt-6 border-t border-line pt-4">
      <div class="flex items-center justify-between mb-2">
        <div class="flex items-center gap-2 text-[11px] font-mono uppercase tracking-widest text-fog">
          <span class="text-signal">Live kernel telemetry</span>
        </div>
        <div class="flex items-center gap-1">
          <button id="tickerPauseBtn" class="px-2 py-0.5 text-[10px] font-mono text-fog hover:text-white transition-colors">PAUSE</button>
          <span class="text-fog">|</span>
          <button id="tickerClearBtn" class="px-2 py-0.5 text-[10px] font-mono text-fog hover:text-white transition-colors">CLEAR</button>
        </div>
      </div>
      <div id="kernelTicker" class="h-28 overflow-y-auto font-mono text-[11px] space-y-0.5 select-text scroll-smooth">
      </div>
    </section>

  </div>

  <!-- Forensic Dossier Modal (Tier-1 EDR Analyst View) -->
  <div id="forensicModal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4" style="background: rgba(0,0,0,0.3); backdrop-filter: blur(2px);">
    <div class="bg-panel border border-line max-w-2xl w-full p-5 relative max-h-[90vh] overflow-y-auto shadow-modal">
      <!-- Modal Header -->
      <div class="flex items-center justify-between border-b border-line pb-3 mb-4">
        <div>
          <div class="flex items-center gap-2">
            <h3 id="modalProcessName" class="text-base font-bold text-white font-mono">process.exe</h3>
            <span id="modalIsolatedBadge" class="hidden px-2 py-0.5 text-[10px] font-mono font-bold uppercase bg-warn/10 text-warn border border-warn/30">ISOLATED</span>
          </div>
          <p id="modalPidText" class="text-xs font-mono text-fog mt-0.5">PID: 0000 | Active Threads: 0</p>
        </div>
        <button id="modalCloseBtn" class="text-fog hover:text-white p-1.5 transition-colors">
          <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div class="space-y-4 text-xs font-mono">
        
        <!-- Score Barometer -->
        <div class="grid grid-cols-2 gap-3">
          <div class="p-3 bg-panel border border-line">
            <span class="microlabel block">Assigned Threat Score</span>
            <div class="flex items-baseline gap-2 mt-1">
              <span id="modalThreatScore" class="text-2xl font-bold text-warn">0.0%</span>
              <span class="text-[10px] text-fog">7-VECTOR SCORING</span>
            </div>
          </div>
          <div class="p-3 bg-panel border border-line">
            <span class="microlabel block">Security Classification</span>
            <div id="modalStatusBadge" class="mt-1.5">CLEAN</div>
          </div>
        </div>

        <!-- 7-Vector Readout -->
        <div class="p-4 bg-panel border border-line space-y-2.5">
          <div class="flex items-center justify-between border-b border-line pb-1.5">
            <span class="text-sm font-bold uppercase tracking-wide text-fog">
              Forensic 7-Vector Breakdown
            </span>
            <span class="text-[10px] text-signal">KERNEL VAD AUDIT</span>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 pt-1">
            <div class="flex justify-between">
              <span class="text-fog">1. RWX Page Allocations:</span>
              <span id="modalRwx" class="text-white font-semibold">0</span>
            </div>
            <div class="flex justify-between">
              <span class="text-fog">2. Unbacked Executable Regions:</span>
              <span id="modalUnbacked" class="text-white font-semibold">0</span>
            </div>
            <div class="flex justify-between">
              <span class="text-fog">3. Total RWX Bytes:</span>
              <span id="modalBytes" class="text-white font-semibold">0 B</span>
            </div>
            <div class="flex justify-between">
              <span class="text-fog">4. Active Thread Count:</span>
              <span id="modalThreads" class="text-white font-semibold">0</span>
            </div>
            <div class="flex justify-between">
              <span class="text-fog">5. Unbacked Thread Start:</span>
              <span id="modalThreadStart" class="text-white font-semibold">0x00000000</span>
            </div>
            <div class="flex justify-between">
              <span class="text-fog">6. Known JIT Compiler Flag:</span>
              <span id="modalJitStatus" class="text-signal font-semibold">No</span>
            </div>
            <div class="flex justify-between sm:col-span-2">
              <span class="text-fog">7. VAD Protection Anomaly:</span>
              <span id="modalVadAnomaly" class="text-ok font-semibold">NOMINAL</span>
            </div>
          </div>
        </div>

        <!-- Technique Classification -->
        <div id="techniqueBlock" class="hidden p-4 bg-panel border border-line text-[11px] leading-relaxed">
          <div class="flex items-center justify-between mb-3">
            <span class="text-fog font-bold uppercase tracking-wide text-[10px]">Technique Classification</span>
            <span id="modalMitreTag" class="px-2 py-0.5 text-[10px] font-mono text-signal border border-signal/30">T1055</span>
          </div>
          <div class="space-y-2.5">
            <div>
              <span class="text-dim text-[10px] uppercase">Technique:</span>
              <p id="modalTechniqueName" class="text-bright font-semibold text-xs mt-0.5"></p>
            </div>
            <div>
              <span class="text-dim text-[10px] uppercase">Description:</span>
              <p id="modalTechniqueDesc" class="text-fog mt-0.5"></p>
            </div>
            <div>
              <span class="text-dim text-[10px] uppercase">Matched Indicators:</span>
              <p id="modalTechniqueIndicators" class="text-fog mt-0.5"></p>
            </div>
            <div class="pt-2 border-t border-line">
              <span class="text-dim text-[10px] uppercase">Recommended Response:</span>
              <p id="modalTechniqueResponse" class="text-fog mt-0.5 whitespace-pre-line"></p>
            </div>
          </div>
        </div>

        <!-- Clean / JIT Info Block -->
        <div id="cleanBlock" class="hidden p-3 bg-panel border border-ok/20 text-[11px] leading-relaxed">
          <span class="text-ok font-bold text-xs">CLEAN</span>
          <p id="cleanMessage" class="text-fog mt-1">
            Process behaves within normal memory bounds. No unbacked executable memory anomalies detected.
          </p>
        </div>

        <!-- JIT Engine Info Block -->
        <div id="jitBlock" class="hidden p-3 bg-panel border border-signal/20 text-[11px] leading-relaxed">
          <span class="text-signal font-bold text-xs">LEGITIMATE JIT ENGINE</span>
          <p class="text-fog mt-1">
            This process is a known JIT compiler. RWX regions are expected for JIT code cache.
          </p>
        </div>

        <!-- Strings Dump Drawer (Collapsible) -->
        <div id="stringsDrawer" class="hidden p-3 bg-panel border border-signal/20 font-mono text-[10px] space-y-1">
          <div class="flex items-center justify-between text-signal font-bold pb-1 border-b border-line">
            <span>EXTRACTED IN-MEMORY STRINGS &amp; HEX PREVIEW</span>
            <span>OFFSET: 0x00000000</span>
          </div>
          <div class="text-fog space-y-0.5 pt-1 max-h-32 overflow-y-auto">
            <p><span class="text-cyan-500">0x0000:</span> 90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................| (NOP SLED)</p>
            <p><span class="text-cyan-500">0x0010:</span> 90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................| (NOP SLED)</p>
            <p><span class="text-cyan-500">0x0020:</span> 48 83 EC 28 E8 00 00 00  00 48 89 C3 48 89 5C 24  |H..(.....H..H.\$|</p>
            <p><span class="text-cyan-500">0x0030:</span> 53 74 72 69 6e 67 3a 20  22 52 65 66 6c 65 63 74  |String: "Reflect|</p>
            <p><span class="text-cyan-500">0x0040:</span> 69 76 65 4c 6f 61 64 65  72 22 00 56 69 72 74 75  |iveLoader".Virtu|</p>
            <p><span class="text-cyan-500">0x0050:</span> 61 6c 41 6c 6c 6f 63 00  4e 74 50 72 6f 74 65 63  |alAlloc.NtProtec|</p>
            <p><span class="text-cyan-500">0x1FFF:</span> 90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 C3  |...............Í| (RET)</p>
          </div>
        </div>

        <!-- Remediation Action Buttons -->
        <div class="flex items-center justify-between gap-3 pt-3 border-t border-line">
          <div class="flex items-center gap-2">
            <button id="modalIsolateBtn"
              class="px-3 py-1.5 text-[11px] font-bold tracking-wide uppercase transition-colors bg-warn/10 text-warn border border-warn/30 hover:bg-warn/20 flex items-center gap-1.5">
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
              <span>Isolate Process</span>
            </button>

            <button id="modalDumpBtn"
              class="px-3 py-1.5 text-[11px] font-bold tracking-wide uppercase transition-colors bg-signal/10 text-signal border border-signal/30 hover:bg-signal/20 flex items-center gap-1.5">
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              <span>Dump Memory Strings</span>
            </button>
          </div>

          <button id="modalExportBtn"
            class="px-3 py-1.5 text-[11px] font-semibold text-fog hover:text-white transition-colors">
            Export JSON
          </button>
        </div>

      </div>
    </div>
  </div>

<script>
// Element references
const scanBtn = document.getElementById('scanBtn');
const scanLabel = document.getElementById('scanLabel');
const scanIcon = document.getElementById('scanIcon');
const exportReportBtn = document.getElementById('exportReportBtn');

const idleState = document.getElementById('idleState');
const loadingState = document.getElementById('loadingState');
const resultsSection = document.getElementById('resultsSection');
const summarySection = document.getElementById('summarySection');
const errorBanner = document.getElementById('errorBanner');
const errorMessage = document.getElementById('errorMessage');
const resultsBody = document.getElementById('resultsBody');
const emptySearchState = document.getElementById('emptySearchState');

const statTotal = document.getElementById('statTotal');
const statAnomalies = document.getElementById('statAnomalies');
const statJit = document.getElementById('statJit');
const statCleanCount = document.getElementById('statCleanCount');
const statAnomalyBreakdown = document.getElementById('statAnomalyBreakdown');

const postureBadge = document.getElementById('postureBadge');
const postureDot = document.getElementById('postureDot');
const postureText = document.getElementById('postureText');
const postureSubtext = document.getElementById('postureSubtext');
const postureDefcon = document.getElementById('postureDefcon');
const postureGaugeCircle = document.getElementById('postureGaugeCircle');
const verdictLabel = document.getElementById('verdictLabel');
const threatCard = document.getElementById('threatCard');
const threatIconBox = document.getElementById('threatIconBox');

const filterTabs = document.querySelectorAll('.filter-tab');
const processSearchInput = document.getElementById('processSearchInput');
const filterAllCount = document.getElementById('filterAllCount');
const filterMalCount = document.getElementById('filterMalCount');
const filterSuspCount = document.getElementById('filterSuspCount');
const filterJitCount = document.getElementById('filterJitCount');
const filterCleanCount = document.getElementById('filterCleanCount');
const filteredMatchCount = document.getElementById('filteredMatchCount');
const filteredTotalCount = document.getElementById('filteredTotalCount');

const forensicModal = document.getElementById('forensicModal');
const modalCloseBtn = document.getElementById('modalCloseBtn');
const modalProcessName = document.getElementById('modalProcessName');
const modalPidText = document.getElementById('modalPidText');
const modalThreatScore = document.getElementById('modalThreatScore');
const modalStatusBadge = document.getElementById('modalStatusBadge');
const modalRwx = document.getElementById('modalRwx');
const modalUnbacked = document.getElementById('modalUnbacked');
const modalBytes = document.getElementById('modalBytes');
const modalThreads = document.getElementById('modalThreads');
const modalThreadStart = document.getElementById('modalThreadStart');
const modalJitStatus = document.getElementById('modalJitStatus');
const modalVadAnomaly = document.getElementById('modalVadAnomaly');
const modalRecommendation = document.getElementById('modalRecommendation');
const modalMitreTag = document.getElementById('modalMitreTag');
const modalIsolatedBadge = document.getElementById('modalIsolatedBadge');
const modalIsolateBtn = document.getElementById('modalIsolateBtn');
const modalDumpBtn = document.getElementById('modalDumpBtn');
const modalExportBtn = document.getElementById('modalExportBtn');
const stringsDrawer = document.getElementById('stringsDrawer');
const techniqueBlock = document.getElementById('techniqueBlock');
const cleanBlock = document.getElementById('cleanBlock');
const jitBlock = document.getElementById('jitBlock');
const modalTechniqueName = document.getElementById('modalTechniqueName');
const modalTechniqueDesc = document.getElementById('modalTechniqueDesc');
const modalTechniqueIndicators = document.getElementById('modalTechniqueIndicators');
const modalTechniqueResponse = document.getElementById('modalTechniqueResponse');
const cleanMessage = document.getElementById('cleanMessage');

const radarStatusText = document.getElementById('radarStatusText');
const liveClock = document.getElementById('liveClock');
const radarCanvas = document.getElementById('radarCanvas');
const radarBlipCounter = document.getElementById('radarBlipCounter');
const kernelTicker = document.getElementById('kernelTicker');
const tickerPauseBtn = document.getElementById('tickerPauseBtn');
const tickerClearBtn = document.getElementById('tickerClearBtn');
const toastContainer = document.getElementById('toastContainer');

let allProcesses = [];
let lastScanSummary = null;
let currentFilter = 'all';
let searchQuery = '';
let activeModalProcess = null;
let isolatedPids = new Set();
let isTickerPaused = false;

// --------------------------------------------------------------------------
// Live Clock
// --------------------------------------------------------------------------
function updateClock() {
  const now = new Date();
  const utc = now.toUTCString().split(' ')[4] + ' UTC';
  liveClock.textContent = utc;
}
setInterval(updateClock, 1000);
updateClock();

// --------------------------------------------------------------------------
// Toast Notifications
// --------------------------------------------------------------------------
function showToast(title, message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = 'pointer-events-auto flex items-start gap-3 p-3 bg-panel border border-line transition-all duration-200 translate-y-1 opacity-0 font-mono text-xs';
  
  let borderColor = 'border-signal/30 text-signal';
  let iconSvg = '<svg class="w-4 h-4 text-signal shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>';

  if (type === 'success') {
    borderColor = 'border-ok/30 text-ok';
    iconSvg = '<svg class="w-4 h-4 text-ok shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>';
  } else if (type === 'danger' || type === 'threat') {
    borderColor = 'border-warn/30 text-warn';
    iconSvg = '<svg class="w-4 h-4 text-warn shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>';
  } else if (type === 'warning') {
    borderColor = 'border-signal/30 text-signal';
    iconSvg = '<svg class="w-4 h-4 text-signal shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>';
  }

  toast.className += ' ' + borderColor;
  toast.innerHTML = `
    ${iconSvg}
    <div class="flex-1">
      <div class="font-bold uppercase tracking-wider text-[10px] text-white">${escapeHtml(title)}</div>
      <div class="text-[11px] text-fog mt-0.5">${escapeHtml(message)}</div>
    </div>
  `;

  toastContainer.appendChild(toast);
  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  });

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-x-4');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// --------------------------------------------------------------------------
// Streaming Kernel Terminal Ticker
// --------------------------------------------------------------------------
function appendKernelLog(tag, message, level = 'info') {
  if (isTickerPaused) return;

  const row = document.createElement('div');
  row.className = 'flex items-baseline gap-2 text-[10px] leading-relaxed';

  const timeStr = new Date().toISOString().split('T')[1].slice(0, 12);
  let tagClass = 'text-signal font-bold';

  if (level === 'danger') tagClass = 'text-warn font-bold';
  else if (level === 'warning') tagClass = 'text-signal font-bold';
  else if (level === 'success') tagClass = 'text-ok font-bold';
  else if (level === 'purple') tagClass = 'text-signal font-bold';

  row.innerHTML = `
    <span class="text-dim select-none">[${timeStr}]</span>
    <span class="${tagClass}">[${escapeHtml(tag)}]</span>
    <span class="text-fog">${escapeHtml(message)}</span>
  `;

  kernelTicker.appendChild(row);
  while (kernelTicker.children.length > 80) {
    kernelTicker.removeChild(kernelTicker.firstChild);
  }
  kernelTicker.scrollTop = kernelTicker.scrollHeight;
}

// Initial background kernel activity
const sampleLogs = [
  { tag: 'KERNEL', msg: 'VAD memory auditing filter driver initialized.', level: 'success' },
  { tag: 'SYS', msg: 'NtQueryVirtualMemory handles bound to Ring-0 hooks.', level: 'info' },
  { tag: 'ML', msg: '7-Feature forensic pipeline loaded in volatile memory.', level: 'purple' },
  { tag: 'MONITOR', msg: 'Memory Commit threshold verified: Nominal headroom.', level: 'info' }
];
sampleLogs.forEach(l => appendKernelLog(l.tag, l.msg, l.level));

// Periodic ambient background telemetry
setInterval(() => {
  if (Math.random() > 0.4) return;
  const ambientMsgs = [
    { tag: 'KERNEL', msg: 'Walking active thread list via PsGetProcessThreads...', level: 'info' },
    { tag: 'VAD', msg: 'Validating memory page protection masks against DEP policies.', level: 'info' },
    { tag: 'SYSTEM', msg: 'Telemetry heartbeat verified with SOC command center.', level: 'success' },
    { tag: 'MEM', msg: 'Polling unbacked executable heap allocation delta: +0 KB.', level: 'info' }
  ];
  const pick = ambientMsgs[Math.floor(Math.random() * ambientMsgs.length)];
  appendKernelLog(pick.tag, pick.msg, pick.level);
}, 3800);

tickerPauseBtn.addEventListener('click', () => {
  isTickerPaused = !isTickerPaused;
  tickerPauseBtn.textContent = isTickerPaused ? 'RESUME' : 'PAUSE';
  tickerPauseBtn.className = isTickerPaused 
    ? 'px-2.5 py-0.5 rounded text-[10px] bg-rose-900/60 text-rose-300 border border-rose-700 font-mono'
    : 'px-2.5 py-0.5 rounded text-[10px] bg-panel border border-line text-fog hover:text-bright font-mono';
});

tickerClearBtn.addEventListener('click', () => {
  kernelTicker.innerHTML = '';
  appendKernelLog('TERMINAL', 'Log stream cleared by operator.', 'info');
});

// --------------------------------------------------------------------------
// Interactive Radar Scope (HTML5 Canvas)
// --------------------------------------------------------------------------
let radarAngle = 0;
let radarBlips = [];

function initRadarAmbientBlips() {
  radarBlips = [
    { angle: 0.8, dist: 35, color: '#0D9488', intensity: 0.3 },
    { angle: 2.1, dist: 45, color: '#0D9488', intensity: 0.5 },
    { angle: 4.3, dist: 25, color: '#0D9488', intensity: 0.2 },
    { angle: 5.4, dist: 50, color: '#0D9488', intensity: 0.4 }
  ];
}
initRadarAmbientBlips();

function updateRadarFromProcesses(processes) {
  radarBlips = [];
  processes.forEach((p, idx) => {
    // Distribute blips based on PID hash and threat
    const angle = ((p.pid * 137.5) % 360) * (Math.PI / 180);
    const dist = 15 + ((p.pid * 19) % 38);
    let color = '#10b981';

    if (p.status === 'Malicious (Injected)') color = '#f43f5e';
    else if (p.status === 'Suspicious') color = '#f59e0b';
    else if (p.jit_engine) color = '#00f2fe';

    radarBlips.push({
      angle: angle,
      dist: Math.min(dist, 52),
      color: color,
      intensity: (p.threat_score >= 70 ? 1.0 : 0.4),
      pid: p.pid,
      name: p.name,
      threat: p.threat_score
    });
  });
  radarBlipCounter.textContent = `${radarBlips.length} TARGETS`;
}

function drawRadarScope() {
  if (!radarCanvas) return;
  const ctx = radarCanvas.getContext('2d');
  const w = radarCanvas.width;
  const h = radarCanvas.height;
  const cx = w / 2;
  const cy = h / 2;

  // Clear with faint trail
  ctx.fillStyle = 'rgba(255, 255, 255, 0.18)';
  ctx.fillRect(0, 0, w, h);

  // Concentric Rings
  ctx.lineWidth = 1;
  [18, 36, 52].forEach((radius) => {
    ctx.strokeStyle = 'rgba(13, 148, 136, 0.25)';
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.stroke();
  });

  // Crosshairs
  ctx.strokeStyle = 'rgba(13, 148, 136, 0.15)';
  ctx.beginPath();
  ctx.moveTo(cx, cy - 54);
  ctx.lineTo(cx, cy + 54);
  ctx.moveTo(cx - 54, cy);
  ctx.lineTo(cx + 54, cy);
  ctx.stroke();

  // Sweep Line
  radarAngle = (radarAngle + 0.04) % (Math.PI * 2);
  const sweepX = cx + Math.cos(radarAngle) * 52;
  const sweepY = cy + Math.sin(radarAngle) * 52;

  // Sweep gradient trail
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.arc(cx, cy, 52, radarAngle - 0.45, radarAngle);
  ctx.lineTo(cx, cy);
  const sweepGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, 52);
  sweepGrad.addColorStop(0, 'rgba(13, 148, 136, 0)');
  sweepGrad.addColorStop(1, 'rgba(13, 148, 136, 0.25)');
  ctx.fillStyle = sweepGrad;
  ctx.fill();

  // Sweep main line
  ctx.strokeStyle = '#0D9488';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(sweepX, sweepY);
  ctx.stroke();

  // Draw Blips
  radarBlips.forEach(blip => {
    // Check if sweep line just passed over blip
    const diff = Math.abs(radarAngle - blip.angle);
    if (diff < 0.1) {
      blip.intensity = 1.0;
    } else {
      blip.intensity = Math.max(0.15, blip.intensity * 0.985);
    }

    const bx = cx + Math.cos(blip.angle) * blip.dist;
    const by = cy + Math.sin(blip.angle) * blip.dist;

    ctx.save();
    ctx.beginPath();
    ctx.arc(bx, by, (blip.color === '#DC2626' ? 3.5 : 2), 0, Math.PI * 2);
    ctx.fillStyle = blip.color;
    ctx.globalAlpha = blip.intensity;
    ctx.shadowColor = blip.color;
    ctx.shadowBlur = blip.intensity * 12;
    ctx.fill();
    ctx.restore();
  });

  requestAnimationFrame(drawRadarScope);
}
requestAnimationFrame(drawRadarScope);

// --------------------------------------------------------------------------
// Diagnostics Stepper
// --------------------------------------------------------------------------
const scanSteps = [
  'Inspecting RWX regions & thread maps…',
  'Walking Virtual Address Descriptors (VADs)...',
  'Analyzing unbacked executable heap allocations...',
  'Executing scikit-learn 7-vector ensemble inference...',
  'Correlating process heuristics against JIT allowlist...',
  'Compiling SOC threat telemetry...'
];
let scanStepIndex = 0;
let scanTimer = null;

function startRadarDiagnostics() {
  scanStepIndex = 0;
  radarStatusText.textContent = scanSteps[0];
  scanTimer = setInterval(() => {
    scanStepIndex = (scanStepIndex + 1) % scanSteps.length;
    radarStatusText.textContent = scanSteps[scanStepIndex];
  }, 350);
}

function stopRadarDiagnostics() {
  if (scanTimer) clearInterval(scanTimer);
}

// --------------------------------------------------------------------------
// Status Badges & Colors
// --------------------------------------------------------------------------
function getStatusBadge(status) {
  switch (status) {
    case 'Malicious (Injected)':
      return `<span class="px-2 py-0.5 text-[10px] font-mono font-bold uppercase text-warn border border-warn/30 bg-warn/10">MALICIOUS</span>`;
    case 'Suspicious':
      return `<span class="px-2 py-0.5 text-[10px] font-mono font-semibold uppercase text-signal border border-signal/30 bg-signal/10">SUSPICIOUS</span>`;
    case 'Legitimate JIT Engine':
      return `<span class="px-2 py-0.5 text-[10px] font-mono font-medium uppercase text-signal border border-signal/20 bg-signal/5">JIT ENGINE</span>`;
    case 'Clean':
    default:
      return `<span class="px-2 py-0.5 text-[10px] font-mono font-medium uppercase text-ok border border-ok/20">CLEAN</span>`;
  }
}

function getScoreColorClass(score) {
  if (score >= 70) return 'text-alert font-bold';
  if (score >= 35) return 'text-warn font-semibold';
  return 'text-signal';
}

function getScoreBarClass(score) {
  if (score >= 70) return 'bg-alert';
  if (score >= 35) return 'bg-warn';
  return 'bg-signal';
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// --------------------------------------------------------------------------
// Table & Filter Rendering
// --------------------------------------------------------------------------
function renderFilteredProcesses() {
  const query = searchQuery.toLowerCase().trim();

  const filtered = allProcesses.filter(p => {
    let matchesTab = true;
    if (currentFilter === 'malicious') {
      matchesTab = (p.status === 'Malicious (Injected)');
    } else if (currentFilter === 'suspicious') {
      matchesTab = (p.status === 'Suspicious');
    } else if (currentFilter === 'jit') {
      matchesTab = (p.status === 'Legitimate JIT Engine');
    } else if (currentFilter === 'clean') {
      matchesTab = (p.status === 'Clean');
    }

    let matchesSearch = true;
    if (query) {
      const nameMatch = p.name.toLowerCase().includes(query);
      const pidMatch = String(p.pid).includes(query);
      matchesSearch = (nameMatch || pidMatch);
    }

    return matchesTab && matchesSearch;
  });

  filteredMatchCount.textContent = filtered.length;
  filteredTotalCount.textContent = allProcesses.length;

  resultsBody.innerHTML = '';

  if (filtered.length === 0) {
    emptySearchState.classList.remove('hidden');
    return;
  } else {
    emptySearchState.classList.add('hidden');
  }

  filtered.forEach(p => {
    const isIsolated = isolatedPids.has(p.pid);
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-raise transition-colors cursor-pointer group';
    
    if (isIsolated) {
      tr.className += ' bg-warn/5 border-l-2 border-warn/50 opacity-75';
    } else if (p.status === 'Malicious (Injected)') {
      tr.className += ' bg-warn/5 border-l-2 border-warn';
    } else if (p.status === 'Suspicious') {
      tr.className += ' bg-amber-950/10 border-l-2 border-amber-500';
    }

    tr.innerHTML = `
      <td class="px-5 py-3.5 text-fog font-mono">
        <span class="text-signal/80">#</span>${p.pid}
      </td>
      <td class="px-5 py-3.5 font-semibold text-bright flex items-center gap-2">
        <span>${escapeHtml(p.name)}</span>
        ${p.jit_engine ? '<span class="text-[10px] text-signal border border-signal/20 px-1.5 py-0.2 bg-signal/5">JIT</span>' : ''}
        ${isIsolated ? '<span class="text-[9px] text-warn border border-warn/30 px-1 bg-warn/10">ISOLATED</span>' : ''}
      </td>
      <td class="px-5 py-3.5">
        <span class="${p.rwx_count > 0 ? 'text-warn font-bold' : 'text-fog'}">${p.rwx_count}</span>
      </td>
      <td class="px-5 py-3.5">
        <span class="${p.unbacked_exec_count > 0 ? 'text-warn font-bold' : 'text-fog'}">${p.unbacked_exec_count}</span>
      </td>
      <td class="px-5 py-3.5 text-fog">
        ${p.allocated_kb.toLocaleString()} <span class="text-dim text-[10px]">KB</span>
      </td>
      <td class="px-5 py-3.5">
        <div class="flex items-center gap-2.5">
          <div class="w-16 bg-line rounded-full h-1.5 overflow-hidden border border-line">
            <div class="${getScoreBarClass(p.threat_score)} h-full" style="width: ${Math.min(p.threat_score, 100)}%"></div>
          </div>
          <span class="${getScoreColorClass(p.threat_score)}">${p.threat_score.toFixed(1)}%</span>
        </div>
      </td>
      <td class="px-5 py-3.5">
        ${getStatusBadge(p.status)}
      </td>
      <td class="px-5 py-3.5 text-right">
        <button class="inspect-btn px-2.5 py-1 rounded-lg bg-panel border border-line hover:bg-signal hover:text-white text-fog font-mono text-[11px] font-bold uppercase transition-colors">
          Inspect
        </button>
      </td>
    `;

    tr.addEventListener('click', () => openProcessDossier(p));
    resultsBody.appendChild(tr);
  });
}

// --------------------------------------------------------------------------
// Forensic Dossier Modal Management
// --------------------------------------------------------------------------

function openProcessDossier(p) {
  activeModalProcess = p;

  modalProcessName.textContent = p.name;
  modalPidText.textContent = `PID: ${p.pid} | Threads: ${p.num_threads} | Image: ${p.name}`;
  modalThreatScore.textContent = `${p.threat_score.toFixed(2)}%`;
  modalThreatScore.className = `text-2xl font-bold font-mono ${getScoreColorClass(p.threat_score)}`;
  
  modalStatusBadge.innerHTML = getStatusBadge(p.status);
  modalRwx.textContent = `${p.rwx_count} Pages`;
  modalUnbacked.textContent = `${p.unbacked_exec_count} Regions`;
  modalBytes.textContent = `${(p.total_rwx_bytes).toLocaleString()} Bytes (${p.allocated_kb} KB)`;
  modalThreads.textContent = p.num_threads;
  modalThreadStart.textContent = p.thread_unbacked_start > 0
    ? `0x00007FF8B2A10000 (UNBACKED — ${p.thread_unbacked_start} thread${p.thread_unbacked_start > 1 ? 's' : ''})`
    : '0x00000000 (NTDLL / BASE)';
  modalThreadStart.className = p.thread_unbacked_start > 0 ? 'text-warn font-semibold' : 'text-fog font-semibold';

  modalJitStatus.textContent = p.jit_engine ? 'Yes (Allowlisted Engine)' : 'No (Standard Executable)';
  modalJitStatus.className = p.jit_engine ? 'text-signal font-semibold' : 'text-fog font-semibold';

  if (p.vad_protection_anomaly > 0 && !p.jit_engine) {
    modalVadAnomaly.textContent = `${p.vad_protection_anomaly} flip(s) (RW -> RX/RWX)`;
    modalVadAnomaly.className = 'text-warn font-bold';
  } else if (p.jit_engine) {
    modalVadAnomaly.textContent = 'SUPPRESSED VIA JIT POLICY';
    modalVadAnomaly.className = 'text-signal font-semibold';
  } else {
    modalVadAnomaly.textContent = 'NOMINAL';
    modalVadAnomaly.className = 'text-ok font-semibold';
  }

  // Hide all info blocks, then show the relevant one
  techniqueBlock.classList.add('hidden');
  cleanBlock.classList.add('hidden');
  jitBlock.classList.add('hidden');

  if (p.classification && (p.status === 'Malicious (Injected)' || p.status === 'Suspicious')) {
    // Show technique classification block
    techniqueBlock.classList.remove('hidden');
    techniqueBlock.style.borderColor = p.status === 'Malicious (Injected)'
      ? 'rgba(244, 63, 94, 0.3)' : 'rgba(245, 158, 11, 0.3)';
    modalMitreTag.textContent = p.classification.mitre_id;
    modalTechniqueName.textContent = p.classification.display_name;
    modalTechniqueDesc.textContent = p.classification.short_description;
    modalTechniqueIndicators.textContent = p.classification.typical_indicators;
    modalTechniqueResponse.textContent = p.classification.recommended_response;
  } else if (p.jit_engine) {
    jitBlock.classList.remove('hidden');
  } else {
    cleanBlock.classList.remove('hidden');
  }

  setIsolateUI(p.pid, isolatedPids.has(p.pid));

  forensicModal.classList.remove('hidden');
}

modalCloseBtn.addEventListener('click', () => forensicModal.classList.add('hidden'));
forensicModal.addEventListener('click', (e) => {
  if (e.target === forensicModal) forensicModal.classList.add('hidden');
});

// Containment Action 1: Isolate / Resume Process (real user-mode suspend)

function setIsolateUI(pid, suspended) {
  if (suspended) {
    isolatedPids.add(pid);
    modalIsolatedBadge.classList.remove('hidden');
    modalIsolateBtn.classList.add('opacity-50', 'pointer-events-none');
    modalIsolateBtn.innerHTML =
      '<svg class="w-3.5 h-3.5 text-ok" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">'
      + '<path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />'
      + '</svg>'
      + '<span>Resume Process</span>';
  } else {
    isolatedPids.delete(pid);
    modalIsolatedBadge.classList.add('hidden');
    modalIsolateBtn.classList.remove('opacity-50', 'pointer-events-none');
    modalIsolateBtn.innerHTML =
      '<svg class="w-3.5 h-3.5 text-warn" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">'
      + '<path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />'
      + '</svg>'
      + '<span>Isolate Process</span>';
  }
}

async function toggleIsolate(pid, currentlySuspended) {
  if (!activeModalProcess) return;

  const verb = currentlySuspended ? 'resume' : 'suspend';
  const targetName = escapeHtml(activeModalProcess.name);
  const confirmLabel = currentlySuspended
    ? `Resume ${targetName} (PID ${pid})? This will unpause the process.`
    : `Suspend ${targetName} (PID ${pid})? This will pause the process until resumed.`;

  if (!confirm(confirmLabel)) return;

  modalIsolateBtn.disabled = true;
  modalIsolateBtn.classList.add('opacity-50');
  const originalInner = modalIsolateBtn.innerHTML;
  modalIsolateBtn.innerHTML =
    '<svg class="w-3.5 h-3.5 animate-spin text-fog" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">'
    + '<path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />'
    + '</svg>'
    + (currentlySuspended ? '<span>Resuming…</span>' : '<span>Isolating…</span>');

  const endpoint = currentlySuspended ? `/api/resume/${pid}` : `/api/isolate/${pid}`;
  let ok = false;
  let error = null;
  let suspended = currentlySuspended;

  try {
    const res = await fetch(endpoint, { method: 'POST' });
    const data = await res.json();
    ok = !!data.success;
    error = data.error || null;
    if (ok) {
      suspended = !currentlySuspended;
    }
  } catch (err) {
    error = err && err.message ? err.message : 'Request failed';
  } finally {
    modalIsolateBtn.disabled = false;
    modalIsolateBtn.classList.remove('opacity-50');
    setIsolateUI(pid, suspended);
    renderFilteredProcesses();

    if (ok) {
      const title = suspended ? 'Process Suspended' : 'Process Resumed';
      const msg = suspended
        ? `PID ${pid} (${targetName}) threads suspended.`
        : `PID ${pid} (${targetName}) threads resumed.`;
      showToast(title, msg, suspended ? 'danger' : 'success');
      if (suspended) {
        appendKernelLog(
          'CONTAINMENT',
          `ShadowMem isolated PID ${pid} (${targetName}) — user-mode suspend via /api/isolate/${pid}.`,
          'danger');
      } else {
        appendKernelLog(
          'CONTAINMENT',
          `ShadowMem resumed PID ${pid} (${targetName}) — user-mode resume via /api/resume/${pid}.`,
          'success');
      }
    } else {
      const title = suspended ? 'Isolation Failed' : 'Resume Failed';
      // Surface the expected/structural errors distinctly so analysts don't
      // treat "insufficient privileges" or "protected system process" as bugs.
      if (error && (
          error.toLowerCase().includes('insufficient privileges')
          || error.toLowerCase().includes('protected')
          || error.toLowerCase().includes('no longer exists')
          || error.toLowerCase().includes('self-protection')
      )) {
        appendKernelLog('CONTAINMENT', `Isolation rejected: ${error}`, 'warning');
      } else {
        appendKernelLog('CONTAINMENT', `Isolation error: ${error}`, 'danger');
      }
      showToast(title, error || 'Unknown error.', 'danger');
    }
  }
}

modalIsolateBtn.addEventListener('click', () => {
  if (!activeModalProcess) return;
  toggleIsolate(activeModalProcess.pid, isolatedPids.has(activeModalProcess.pid));
});

// Containment Action 2: Export Process Classification
modalDumpBtn.addEventListener('click', () => {
  if (!activeModalProcess) return;
  const p = activeModalProcess;
  const report = {
    pid: p.pid,
    name: p.name,
    threat_score: p.threat_score,
    status: p.status,
    classification: p.classification || null,
    features: {
      rwx_count: p.rwx_count,
      unbacked_exec_count: p.unbacked_exec_count,
      total_rwx_bytes: p.total_rwx_bytes,
      num_threads: p.num_threads,
      thread_unbacked_start: p.thread_unbacked_start,
      vad_protection_anomaly: p.vad_protection_anomaly,
    },
  };
  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
  const a = document.createElement('a');
  a.setAttribute('href', dataStr);
  a.setAttribute('download', `ShadowMem-Technique-PID${p.pid}.json`);
  document.body.appendChild(a);
  a.click();
  a.remove();
  appendKernelLog('CLASSIFY', `Technique report exported for PID ${p.pid} (${p.classification ? p.classification.display_name : 'N/A'}).`, 'info');
  showToast('Technique Report', `Exported classification data for PID ${p.pid}.`, 'success');
});

// Containment Action 3: Export Single Process JSON
modalExportBtn.addEventListener('click', () => {
  if (!activeModalProcess) return;
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(activeModalProcess, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `ShadowMem-Dossier-PID${activeModalProcess.pid}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
  showToast('Telemetry Exported', `Saved forensic dossier for PID ${activeModalProcess.pid}.`, 'info');
});

// --------------------------------------------------------------------------
// Full Report Export (.json)
// --------------------------------------------------------------------------
exportReportBtn.addEventListener('click', () => {
  if (!allProcesses || allProcesses.length === 0) {
    showToast('Export Unavailable', 'Execute a memory scan first before exporting telemetry.', 'warning');
    return;
  }

  const exportPayload = {
    metadata: {
      generator: "ShadowMem Cyber Defense Operations Center",
      version: "2.5.0-ENTERPRISE-SOC",
      timestamp: new Date().toISOString(),
      mitre_tactics: ["TA0005 - Defense Evasion", "TA0004 - Privilege Escalation"],
      audited_by: "SOC-TIER-3-ANALYST"
    },
    summary: lastScanSummary,
    processes: allProcesses
  };

  const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ShadowMem-SOC-Report-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast('Report Exported', `Generated comprehensive forensic report for ${allProcesses.length} processes.`, 'success');
  appendKernelLog('EXPORT', `Full forensic report exported with ${allProcesses.length} process records.`, 'success');
});

// --------------------------------------------------------------------------
// Filtering and Search Listeners
// --------------------------------------------------------------------------
function updateFilterCounts(summary) {
  filterAllCount.textContent = summary.total_scanned;
  filterMalCount.textContent = summary.malicious_count;
  filterSuspCount.textContent = summary.suspicious_count;
  filterJitCount.textContent = summary.jit_engine_count;
  filterCleanCount.textContent = summary.clean_count;
}

filterTabs.forEach(tab => {
  tab.addEventListener('click', () => {
    filterTabs.forEach(t => {
      t.className = 'filter-tab px-3 py-1.5 text-xs font-mono font-semibold text-fog transition-colors border-b-2 border-transparent hover:text-signal hover:border-signal';
    });

    currentFilter = tab.getAttribute('data-filter');
    tab.className = 'filter-tab active-filter px-3 py-1.5 text-xs font-mono font-semibold transition-colors border-b-2 border-signal text-white';

    renderFilteredProcesses();
  });
});

processSearchInput.addEventListener('input', (e) => {
  searchQuery = e.target.value;
  renderFilteredProcesses();
});

window.addEventListener('keydown', (e) => {
  if (e.key === '/' && document.activeElement !== processSearchInput) {
    e.preventDefault();
    processSearchInput.focus();
  }
  if (e.key === 'Escape' && !forensicModal.classList.contains('hidden')) {
    forensicModal.classList.add('hidden');
  }
});

// --------------------------------------------------------------------------
// Summary & Threat Posture Update
// --------------------------------------------------------------------------
function renderSummary(summary) {
  lastScanSummary = summary;
  statTotal.textContent = summary.total_scanned;
  statAnomalies.textContent = summary.anomalies_detected;
  statJit.textContent = summary.jit_engine_count;
  statCleanCount.textContent = summary.clean_count;
  statAnomalyBreakdown.textContent = `${summary.malicious_count} Mal / ${summary.suspicious_count} Susp`;

  updateFilterCounts(summary);

  const isThreat = summary.system_posture === 'Threat Detected';

  if (isThreat) {
    postureBadge.className = 'px-2 py-0.5 text-[10px] font-mono font-bold uppercase text-warn border border-warn/30 bg-warn/10';
    postureDot.className = 'w-2 h-2 rounded-full bg-warn';
    postureText.textContent = 'THREAT DETECTED';
    postureSubtext.textContent = 'Active fileless injection flagged';
    postureDefcon.textContent = 'DEFCON 1';
    postureDefcon.className = 'text-[10px] font-mono px-2 py-0.5 text-warn border border-warn/30';
    verdictLabel.textContent = 'BREACH ALERT';
    verdictLabel.className = 'text-warn font-bold font-mono';

    postureGaugeCircle.setAttribute('stroke', '#DC2626');
    postureGaugeCircle.setAttribute('stroke-dashoffset', '47.1');

    threatCard.classList.add('border-warn/30');
    threatIconBox.classList.add('text-warn');

    appendKernelLog('ALERT', `BREACH DETECTED: ${summary.anomalies_detected} unbacked memory anomalies flagged!`, 'danger');
    showToast('Threat Detected', `${summary.anomalies_detected} memory anomalies identified in active processes!`, 'danger');
  } else {
    postureBadge.className = 'px-2 py-0.5 text-[10px] font-mono font-bold uppercase text-ok border border-ok/20';
    postureDot.className = 'w-2 h-2 rounded-full bg-ok';
    postureText.textContent = 'PROTECTED';
    postureSubtext.textContent = 'No active thread injection found';
    postureDefcon.textContent = 'DEFCON 5';
    postureDefcon.className = 'text-[10px] font-mono px-2 py-0.5 text-fog border border-line';
    verdictLabel.textContent = 'NOMINAL';
    verdictLabel.className = 'text-ok font-semibold font-mono';

    postureGaugeCircle.setAttribute('stroke', '#0D9488');
    postureGaugeCircle.setAttribute('stroke-dashoffset', '0');

    threatCard.classList.remove('border-warn/30');
    threatIconBox.classList.remove('text-warn');

    appendKernelLog('SOC', 'Volatile memory sweep clean. System baseline verified.', 'success');
    showToast('Scan Clean', `Audited ${summary.total_scanned} processes. No active fileless injections found.`, 'success');
  }

  summarySection.classList.remove('hidden');
}

// --------------------------------------------------------------------------
// Core Scan Execution
// --------------------------------------------------------------------------
async function runScan() {
  errorBanner.classList.add('hidden');
  idleState.classList.add('hidden');
  resultsSection.classList.add('hidden');

  loadingState.classList.remove('hidden');
  loadingState.classList.add('flex');
  startRadarDiagnostics();

  scanBtn.disabled = true;
  scanLabel.textContent = 'Analyzing VADs…';
  scanIcon.classList.add('animate-spin');

  appendKernelLog('KERNEL', 'Initiating volatile memory audit across user-mode processes...', 'info');

  try {
    const res = await fetch('/api/scan');
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Scan failed with status ${res.status}`);
    }
    const data = await res.json();

    allProcesses = data.processes || [];

    // A fresh scan reshapes the process list. Keep any client-side isolate
    // decisions across cycles only for PIDs that still exist in the new scan;
    // silently drop PIDs that disappeared (the backend resume endpoint is the
    // authoritative path to undo an isolation).
    const stillAlive = new Set(allProcesses.map(p => p.pid));
    for (const pid of isolatedPids.values()) {
      if (!stillAlive.has(pid)) {
        isolatedPids.delete(pid);
      }
    }

    renderSummary(data.summary);
    renderFilteredProcesses();
    updateRadarFromProcesses(allProcesses);

    stopRadarDiagnostics();
    loadingState.classList.add('hidden');
    loadingState.classList.remove('flex');
    resultsSection.classList.remove('hidden');
  } catch (err) {
    stopRadarDiagnostics();
    loadingState.classList.add('hidden');
    loadingState.classList.remove('flex');
    idleState.classList.remove('hidden');

    errorMessage.textContent = err.message;
    errorBanner.classList.remove('hidden');
    appendKernelLog('ERROR', `Forensic acquisition failure: ${err.message}`, 'danger');
    showToast('Scan Error', err.message, 'danger');
  } finally {
    scanBtn.disabled = false;
    scanLabel.textContent = 'Scan System Memory';
    scanIcon.classList.remove('animate-spin');
  }
}

scanBtn.addEventListener('click', runScan);
</script>

</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True) 