import ctypes
from ctypes import wintypes
import psutil

# ---------------------------------------------------------------------------
# Win32 constants
# ---------------------------------------------------------------------------
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
THREAD_QUERY_INFORMATION = 0x0040

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

# Protections that make a region executable (RWX, RX, or copy-on-write exec)
_EXEC_PROTECTIONS = {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}

# ntdll THREADINFOCLASS: ThreadQuerySetWin32StartAddress
ThreadQuerySetWin32StartAddress = 9

# ---------------------------------------------------------------------------
# Structures / handles
# ---------------------------------------------------------------------------
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

kernel32.OpenThread.restype = ctypes.c_void_p
kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
]

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

ntdll.NtQueryInformationThread.restype = ctypes.c_long  # NTSTATUS
ntdll.NtQueryInformationThread.argtypes = [
    ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p,
    ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
]


def _query_region(h_process, address):
    """VirtualQueryEx wrapper; returns (valid, mbi) with a fresh MBI."""
    mbi = MEMORY_BASIC_INFORMATION()
    ok = kernel32.VirtualQueryEx(
        h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
    )
    return bool(ok), mbi


def _get_thread_start_address(thread_handle):
    """Resolve a thread's Win32 start address via ntdll. Returns int or None."""
    start_addr = ctypes.c_ulonglong(0)
    return_len = ctypes.c_ulong(0)
    status = ntdll.NtQueryInformationThread(
        thread_handle,
        ThreadQuerySetWin32StartAddress,
        ctypes.byref(start_addr),
        ctypes.sizeof(start_addr),
        ctypes.byref(return_len),
    )
    if status != 0:  # NTSTATUS success is 0 (STATUS_SUCCESS)
        return None
    return start_addr.value


def inspect_process(pid: int) -> dict:
    features = {
        "pid": pid,
        "name": "Unknown",
        "exe": "",
        "rwx_count": 0,
        "unbacked_exec_count": 0,
        "total_rwx_bytes": 0,
        "num_threads": 0,
        "thread_unbacked_start": 0,
        "vad_protection_anomaly": 0,
        "error": None,
    }

    try:
        proc = psutil.Process(pid)
        features["name"] = proc.name()
        try:
            features["exe"] = proc.exe() or ""
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            features["exe"] = ""
        features["num_threads"] = proc.num_threads()
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
        features["error"] = "Access Denied"
        return features

    h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h_process:
        features["error"] = "Access Denied"
        return features

    try:
        # ---- Region walk: rwx/unbacked counts + vad_protection_anomaly ----
        address = 0
        while True:
            ok, mbi = _query_region(h_process, address)
            if not ok:
                break
            region_size = mbi.RegionSize or 0x1000
            if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE:
                protect = mbi.Protect
                if protect in _EXEC_PROTECTIONS:
                    features["unbacked_exec_count"] += 1
                    if protect == PAGE_EXECUTE_READWRITE:
                        features["rwx_count"] += 1
                        features["total_rwx_bytes"] += region_size
                    # RW -> RX/RWX flip: the allocation was originally created
                    # as data (PAGE_READWRITE) and later flipped to executable
                    # via VirtualProtect - the classic self-injection pattern.
                    # Originally-executable allocations do not count.
                    if mbi.AllocationProtect == PAGE_READWRITE:
                        features["vad_protection_anomaly"] += 1
            address += region_size
            if address >= 0x7FFFFFFEFFFF:  # user-space ceiling on x64
                break

        # ---- Threads: thread_unbacked_start (shellcode-thread signature) ----
        try:
            thread_infos = proc.threads()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            thread_infos = []

        for tinfo in thread_infos:
            h_thread = kernel32.OpenThread(THREAD_QUERY_INFORMATION, False, tinfo.id)
            if not h_thread:
                continue
            try:
                start_addr = _get_thread_start_address(h_thread)
            finally:
                kernel32.CloseHandle(h_thread)
            if not start_addr:
                continue
            ok, mbi = _query_region(h_process, start_addr)
            if not ok:
                continue
            if (
                mbi.State == MEM_COMMIT
                and mbi.Type == MEM_PRIVATE
                and mbi.Protect in _EXEC_PROTECTIONS
            ):
                features["thread_unbacked_start"] += 1
    finally:
        kernel32.CloseHandle(h_process)

    return features

def scan_all_processes():
    """Returns a list of feature dictionaries for active processes."""
    results = []
    for proc in psutil.process_iter(['pid']):
        try:
            info = inspect_process(proc.info['pid'])
            if not info.get("error"):
                results.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results