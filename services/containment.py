"""
services/containment.py
=======================
Process isolation (containment), thread suspension/resumption, and audit tracking.
Safeguards critical operating system processes and ShadowMem's own worker process.
"""

import ctypes
from ctypes import wintypes
import datetime as _dt
import logging
from typing import List, Dict, Tuple, Optional, Any

from core.config import settings
from core.logging import logger
from services.forensics import get_cached_processes

# ---- Win32 Constants & Function Signatures ---------------------------------
INVALID_HANDLE_VALUE = -1

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

# In-memory audit trail of isolation actions
_isolation_audit: List[Dict[str, Any]] = []


def record_audit(pid: int, name: str, action: str, ok: bool, reason: Optional[str] = None) -> None:
    """Record a containment action in the in-memory audit log."""
    _isolation_audit.append({
        "pid": pid,
        "name": name,
        "action": action,
        "success": ok,
        "reason": reason,
        "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    })
    logger.info(
        "isolation audit %s pid=%s name=%s ok=%s reason=%s",
        action, pid, name, ok, reason,
    )


def get_audit_trail() -> List[Dict[str, Any]]:
    """Return a copy of the audit trail."""
    return list(_isolation_audit)


def iter_threads(pid: int):
    """Yield (thread_id, thread_handle) for every live thread in |pid|."""
    try:
        import psutil as _psutil
        proc = _psutil.Process(pid)
        for td in proc.threads():
            h = _OPEN_THREAD(THREAD_SUSPEND_RESUME, False, td.id)
            if h and h != INVALID_HANDLE_VALUE:
                yield td.id, h
    except Exception:
        pass


def _lookup_process_name(pid: int) -> str:
    """Find human-readable process name from cached scan or psutil."""
    for p in get_cached_processes():
        if int(p.get("pid", -1)) == pid:
            return str(p.get("name", "unknown"))

    try:
        import psutil as _psutil
        return _psutil.Process(pid).name() or "unknown"
    except Exception:
        return f"pid:{pid}"


def isolate_process(pid: int, reason: str = "") -> Tuple[int, Dict[str, Any]]:
    """
    Suspend every thread in a target user-mode process.
    Returns (status_code, response_data).
    """
    if pid is None or pid <= 0:
        return 400, {"success": False, "error": "Invalid PID.", "action": "suspended"}

    # Self-protection
    try:
        our_pid = _K32.GetCurrentProcessId()
        protected_pids = {our_pid}
        try:
            import psutil as _psutil
            ppid = _psutil.Process(our_pid).ppid()
            if ppid:
                protected_pids.add(ppid)
        except Exception:
            pass

        if pid in protected_pids:
            msg = "Refusing to isolate ShadowMem's own process (self-protection)."
            record_audit(pid, "shadowmem", "isolate", False, msg)
            return 403, {"success": False, "error": msg, "action": "suspended"}
    except Exception:  # noqa: BLE001
        pass

    name = _lookup_process_name(pid)
    lower_name = name.lower().strip()

    # Protected OS process blocklist
    if lower_name in settings.critical_system_processes or any(
        lower_name == x or lower_name.startswith(x) for x in ("csrss", "smss")
    ):
        msg = f"Refusing to isolate {repr(name)} (PID {pid}): this is a protected system process. Suspending it can destabilize or crash Windows."
        record_audit(pid, name, "isolate", False, msg)
        return 403, {"success": False, "error": msg, "action": "suspended"}

    handle = None
    handles = []
    try:
        handle = _OPEN_PROCESS(PROCESS_SUSPEND_RESUME, False, pid)
        if not handle or handle == INVALID_HANDLE_VALUE:
            err = _K32.GetLastError()
            if err == 5:
                msg = f"Cannot isolate {repr(name)} (PID {pid}): insufficient privileges. The process is owned by another user / admin / SYSTEM and cannot be opened from this ShadowMem instance."
                record_audit(pid, name, "isolate", False, msg)
                return 403, {"success": False, "error": msg, "action": "suspended"}
            if err in (2, 87):
                msg = f"Process {repr(name)} (PID {pid}) no longer exists."
                record_audit(pid, name, "isolate", False, msg)
                return 404, {"success": False, "error": msg, "action": "suspended"}
            msg = f"Cannot open process {repr(name)} (PID {pid}): Win32 error {err}."
            record_audit(pid, name, "isolate", False, msg)
            return 500, {"success": False, "error": msg, "action": "suspended"}

        suspended = 0
        failed = 0
        for _tid, h in iter_threads(pid):
            try:
                rc = _SUSPEND_THREAD(h)
                if rc == -1:
                    err = _K32.GetLastError()
                    if err == 5:
                        failed += 1
                        continue
                    exit_code = wintypes.DWORD()
                    if _GET_EXIT_CODE_THREAD(h, ctypes.byref(exit_code)) and exit_code.value != STILL_ACTIVE:
                        continue
                    suspended += 1
                    continue
                suspended += 1
            finally:
                handles.append(h)

        # Fallback NtSuspendProcess
        if suspended == 0 and failed == 0 and handle:
            try:
                _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
                _NtSuspendProcess = _ntdll.NtSuspendProcess
                _NtSuspendProcess.argtypes = (wintypes.HANDLE,)
                _NtSuspendProcess.restype = ctypes.c_long
                status = _NtSuspendProcess(handle)
                if status == 0:
                    suspended = max(suspended, 1)
            except Exception:
                pass

        if suspended == 0 and failed == 0 and not handle:
            msg = f"No threads could be opened for {repr(name)} (PID {pid})."
            record_audit(pid, name, "isolate", False, msg)
            return 403, {"success": False, "error": msg, "action": "suspended"}

        detail_parts = [f"suspended {suspended} thread(s)"]
        if failed:
            detail_parts.append(f"{failed} thread(s) could not be opened (protected / inaccessible)")
        if suspended == 0 and failed > 0:
            msg = f"Partial isolation of {repr(name)} (PID {pid}): {'; '.join(detail_parts)}. The process may already be suspended or protected."
            record_audit(pid, name, "isolate", True, msg)
            return 200, {
                "pid": pid,
                "name": name,
                "action": "suspended",
                "success": True,
                "error": msg,
                "suspended_count": suspended,
                "failed_count": failed,
            }

        msg = f"Isolated {repr(name)} (PID {pid}): suspended {suspended} thread(s)."
        if reason:
            msg += f" Reason: {reason}"
        record_audit(pid, name, "isolate", True, msg)
        return 200, {
            "pid": pid,
            "name": name,
            "action": "suspended",
            "success": True,
            "error": None,
            "suspended_count": suspended,
            "failed_count": failed,
        }

    except Exception as exc:  # noqa: BLE001
        msg = f"Unexpected error isolating {repr(name)} (PID {pid}): {exc!r}"
        record_audit(pid, name, "isolate", False, msg)
        logger.exception("isolate endpoint crashed for pid=%s", pid)
        return 500, {"success": False, "error": msg, "action": "suspended"}

    finally:
        for h in handles:
            try:
                if h and h != INVALID_HANDLE_VALUE:
                    _CLOSE_HANDLE(h)
            except Exception:
                pass
        if handle and handle != INVALID_HANDLE_VALUE:
            try:
                _CLOSE_HANDLE(handle)
            except Exception:
                pass


def resume_process(pid: int) -> Tuple[int, Dict[str, Any]]:
    """
    Resume a previously-suspended process (undo isolation).
    Returns (status_code, response_data).
    """
    if pid is None or pid <= 0:
        return 400, {"success": False, "error": "Invalid PID.", "action": "resumed"}

    name = _lookup_process_name(pid)
    handle = None
    handles = []
    try:
        handle = _OPEN_PROCESS(PROCESS_SUSPEND_RESUME, False, pid)
        if not handle or handle == INVALID_HANDLE_VALUE:
            err = _K32.GetLastError()
            if err == 5:
                msg = f"Cannot resume {repr(name)} (PID {pid}): insufficient privileges."
                record_audit(pid, name, "resume", False, msg)
                return 403, {"success": False, "error": msg, "action": "resumed"}
            if err in (2, 87):
                msg = f"Process {repr(name)} (PID {pid}) no longer exists."
                record_audit(pid, name, "resume", False, msg)
                return 404, {"success": False, "error": msg, "action": "resumed"}
            msg = f"Cannot open process {repr(name)} (PID {pid}): Win32 error {err}."
            record_audit(pid, name, "resume", False, msg)
            return 500, {"success": False, "error": msg, "action": "resumed"}

        resumed = 0
        failed = 0
        for _tid, h in iter_threads(pid):
            try:
                rc = _RESUME_THREAD(h)
                if rc == -1:
                    err = _K32.GetLastError()
                    if err == 5:
                        failed += 1
                        continue
                    if err == 30:
                        pass
                    else:
                        exit_code = wintypes.DWORD()
                        if _GET_EXIT_CODE_THREAD(h, ctypes.byref(exit_code)) and exit_code.value != STILL_ACTIVE:
                            continue
                        failed += 1
                        continue
                while rc > 1:
                    rc = _RESUME_THREAD(h)
                    if rc in (-1, 0):
                        break
                resumed += 1
            finally:
                handles.append(h)

        # Fallback NtResumeProcess
        if resumed == 0 and failed == 0 and handle:
            try:
                _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
                _NtResumeProcess = _ntdll.NtResumeProcess
                _NtResumeProcess.argtypes = (wintypes.HANDLE,)
                _NtResumeProcess.restype = ctypes.c_long
                status = _NtResumeProcess(handle)
                if status == 0:
                    resumed = max(resumed, 1)
            except Exception:
                pass

        if resumed == 0 and failed == 0 and not handle:
            msg = f"No threads could be opened for {repr(name)} (PID {pid})."
            record_audit(pid, name, "resume", False, msg)
            return 403, {"success": False, "error": msg, "action": "resumed"}

        detail_parts = [f"resumed {resumed} thread(s)"]
        if failed:
            detail_parts.append(f"{failed} thread(s) could not be opened (protected / inaccessible)")
        if resumed == 0 and failed > 0:
            msg = f"Partial resume of {repr(name)} (PID {pid}): {'; '.join(detail_parts)}."
            record_audit(pid, name, "resume", True, msg)
            return 200, {
                "pid": pid,
                "name": name,
                "action": "resumed",
                "success": True,
                "error": msg,
                "resumed_count": resumed,
                "failed_count": failed,
            }

        msg = f"Resumed {repr(name)} (PID {pid}): resumed {resumed} thread(s)."
        record_audit(pid, name, "resume", True, msg)
        return 200, {
            "pid": pid,
            "name": name,
            "action": "resumed",
            "success": True,
            "error": None,
            "resumed_count": resumed,
            "failed_count": failed,
        }

    except Exception as exc:  # noqa: BLE001
        msg = f"Unexpected error resuming {repr(name)} (PID {pid}): {exc!r}"
        record_audit(pid, name, "resume", False, msg)
        logger.exception("resume endpoint crashed for pid=%s", pid)
        return 500, {"success": False, "error": msg, "action": "resumed"}

    finally:
        for h in handles:
            try:
                if h and h != INVALID_HANDLE_VALUE:
                    _CLOSE_HANDLE(h)
            except Exception:
                pass
        if handle and handle != INVALID_HANDLE_VALUE:
            try:
                _CLOSE_HANDLE(handle)
            except Exception:
                pass


def refresh_isolated_set() -> None:
    """Best-effort refresh of the frontend's isolated-PID set."""
    try:
        import psutil as _psutil
        for p in get_cached_processes():
            try:
                _proc = _psutil.Process(int(p.get("pid", -1)))
            except Exception:
                pass
    except Exception:
        pass
