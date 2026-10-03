#!/usr/bin/env python3
"""
================================================================================
ShadowMem Security Validation Suite - Synthetic In-Memory Injection Harness
================================================================================
File: test_injector.py
Role: Cybersecurity Systems Engineer & Windows Internals Developer

Overview:
    This script acts as a safe, self-contained test fixture designed to validate
    volatile memory forensic engines such as "ShadowMem". It simulates key
    forensic indicators associated with fileless malware, shellcode staging,
    and reflective DLL loading inside its own virtual address space without
    executing malicious operations or modifying external system resources.

Forensic Indicators Simulated:
    1. Unbacked Executable Memory (MEM_PRIVATE):
       Memory allocated via VirtualAlloc with lpAddress=NULL is private and not
       mapped to an on-disk image file (unlike legitimate DLLs/modules).
    2. W^X / DEP Violation (PAGE_EXECUTE_READWRITE):
       Simulates shellcode staging or in-place unpacking where a memory page
       is granted concurrent Write and Execute privileges (0x40).
    3. Benign Payload Sled:
       Populates the allocation with a classic NOP sled (0x90) terminated by
       a return instruction (0xC3), mirroring executable shellcode signatures.
    4. Multi-Threaded Execution Profile:
       Spawns an auxiliary telemetry thread to reflect realistic worker/beacon
       thread counts expected during live forensic triage.
    5. RW -> RWX Protection Flip (vad_protection_anomaly):
       A second region is allocated PAGE_READWRITE and later flipped to
       PAGE_EXECUTE_READWRITE via VirtualProtect in the SAME process, the
       classic self-injection pattern (allocation created as data, promoted
       to executable after payload staging).
    6. Thread Start in Unbacked Memory (thread_unbacked_start):
       A raw Win32 worker thread is created whose start address points
       directly into the flipped region, mirroring the CreateRemoteThread /
       shellcode-entry telemetry that dynamic EDR features key on.

Safety Guarantee:
    - No remote process injection (OpenProcess / VirtualAllocEx / CreateRemoteThread).
    - No execution of untrusted machine code. The only bytes ever executed are
      the two self-authored EB FE ("jmp $") spin bytes written by this script
      into its own memory; the NOP sled payload itself remains static.
    - All modifications are confined to this process's own address space.
    - Full resource cleanup (thread termination + VirtualFree) on shutdown.
================================================================================
"""

import ctypes
from ctypes import wintypes
import os
import sys
import threading
import time

# ------------------------------------------------------------------------------
# Win32 API Constants & Prototypes
# ------------------------------------------------------------------------------

# Memory Allocation Types (flAllocationType)
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000

# Memory Free Types (dwFreeType)
MEM_RELEASE = 0x00008000

# Memory Protection Constants (flProtect)
PAGE_READWRITE = 0x00000004
PAGE_EXECUTE_READWRITE = 0x00000040

# Allocation Sizing: 128 KB (131,072 bytes)
ALLOCATION_SIZE = 128 * 1024
# Flip-region sizing: one page (4 KB)
FLIP_REGION_SIZE = 4 * 1024

# Explicitly load kernel32 with last-error preservation
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# LPVOID VirtualAlloc(
#   [in, optional] LPVOID lpAddress,
#   [in]           SIZE_T dwSize,
#   [in]           DWORD  flAllocationType,
#   [in]           DWORD  flProtect
# );
kernel32.VirtualAlloc.argtypes = [
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
    wintypes.DWORD,
]
kernel32.VirtualAlloc.restype = wintypes.LPVOID

# BOOL VirtualFree(
#   [in] LPVOID lpAddress,
#   [in] SIZE_T dwSize,
#   [in] DWORD  dwFreeType
# );
kernel32.VirtualFree.argtypes = [
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
]
kernel32.VirtualFree.restype = wintypes.BOOL

# DWORD VirtualProtect(
#   [in]  LPVOID lpAddress,
#   [in]  SIZE_T dwSize,
#   [in]  DWORD  flNewProtect,
#   [out] PDWORD lpflOldProtect
# );
kernel32.VirtualProtect.argtypes = [
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.VirtualProtect.restype = wintypes.BOOL

# HANDLE CreateThread(...) -- lpStartAddress is passed as a raw void pointer
# so the thread can start at an arbitrary address inside our own buffer.
kernel32.CreateThread.restype = wintypes.HANDLE
kernel32.CreateThread.argtypes = [
    wintypes.LPVOID,            # lpThreadAttributes
    ctypes.c_size_t,            # dwStackSize
    wintypes.LPVOID,            # lpStartAddress (raw address)
    wintypes.LPVOID,            # lpParameter
    wintypes.DWORD,             # dwCreationFlags
    ctypes.POINTER(wintypes.DWORD),  # lpThreadId
]

# BOOL TerminateThread(...) -- teardown for the raw spin thread
kernel32.TerminateThread.restype = wintypes.BOOL
kernel32.TerminateThread.argtypes = [wintypes.HANDLE, wintypes.DWORD]

# BOOL CloseHandle(...) -- release kernel object handles after TerminateThread
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


# ------------------------------------------------------------------------------
# Benign Background Worker Thread
# ------------------------------------------------------------------------------

def telemetry_worker(stop_event: threading.Event) -> None:
    """
    Lightweight background worker simulating auxiliary thread activity
    (e.g., C2 beaconing or worker loops) without executing any harmful operations.
    Keeps process thread metrics active for forensic scanners like psutil / NtQuerySystemInformation.
    """
    counter = 0
    while not stop_event.is_set():
        counter += 1
        # Low frequency sleep to avoid CPU load
        time.sleep(1.0)


# ------------------------------------------------------------------------------
# Core Harness Implementation
# ------------------------------------------------------------------------------

def main() -> None:
    pid = os.getpid()
    print("=" * 80)
    print("  SHADOWMEM TEST HARNESS : IN-MEMORY FILELESS ARTIFACT SIMULATOR")
    print("=" * 80)
    print(f"[*] Process Initialized: PID = {pid} ({os.path.basename(sys.executable)})")
    print("[*] Target Architecture: 64-bit Windows OS")
    print("-" * 80)

    # 1. Allocate Anonymous Unbacked Memory with RWX Permissions
    print("[*] Requesting private virtual memory via kernel32.VirtualAlloc...")
    allocation_flags = MEM_COMMIT | MEM_RESERVE
    protection_flags = PAGE_EXECUTE_READWRITE

    base_address = kernel32.VirtualAlloc(
        None,
        ALLOCATION_SIZE,
        allocation_flags,
        protection_flags
    )

    if not base_address:
        error_code = ctypes.get_last_error()
        error_msg = ctypes.FormatError(error_code)
        print(f"[-] FATAL: VirtualAlloc failed with error {error_code}: {error_msg}")
        sys.exit(1)

    print(f"[+] Memory Region Successfully Allocated at: 0x{base_address:016X}")

    # 2. Stage Benign Non-Damaging Instructions (NOP Sled + RET)
    print("[*] Populating buffer with benign shellcode simulation pattern...")
    # 0x90 = NOP (x86/x64 instruction)
    # 0xC3 = RET (near return instruction)
    # In the impossible event of control flow transfer, this safely returns without damage.
    payload = b"\x90" * (ALLOCATION_SIZE - 1) + b"\xC3"
    ctypes.memmove(base_address, payload, ALLOCATION_SIZE)
    print(f"[+] Staged {len(payload):,} bytes (NOP sled [0x90] terminating in RET [0xC3])")

    # 2b. RW -> RWX Protection Flip (self-process only)
    # Region is created as ordinary data memory, then promoted to RWX via
    # VirtualProtect -- the vad_protection_anomaly signature. A raw spin
    # thread (EB FE "jmp $", two self-authored bytes) is started at its base
    # so its Win32 start address lands in unbacked executable memory -- the
    # thread_unbacked_start signature.
    print("[*] Allocating data region and flipping protection RW -> RWX...")
    flip_region = kernel32.VirtualAlloc(
        None, FLIP_REGION_SIZE, allocation_flags, PAGE_READWRITE
    )
    if not flip_region:
        error_code = ctypes.get_last_error()
        print(f"[-] FATAL: VirtualAlloc (flip region) failed with error {error_code}")
        kernel32.VirtualFree(base_address, 0, MEM_RELEASE)
        sys.exit(1)

    old_protect = wintypes.DWORD(0)
    if not kernel32.VirtualProtect(
        flip_region, FLIP_REGION_SIZE, PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect),
    ):
        error_code = ctypes.get_last_error()
        print(f"[-] FATAL: VirtualProtect failed with error {error_code}")
        kernel32.VirtualFree(flip_region, 0, MEM_RELEASE)
        kernel32.VirtualFree(base_address, 0, MEM_RELEASE)
        sys.exit(1)
    ctypes.memmove(flip_region, b"\xEB\xFE", 2)  # spin loop, never returns on its own
    print(
        f"[+] Region 0x{flip_region:016X} flipped RW -> RWX "
        f"(old protection: 0x{old_protect.value:08X})"
    )

    # 3. Spawn Lightweight Background Worker Thread
    stop_event = threading.Event()
    worker = threading.Thread(
        target=telemetry_worker,
        args=(stop_event,),
        name="ShadowMem-BenignTelemetryWorker",
        daemon=True
    )
    worker.start()
    print("[+] Background telemetry worker thread started (maintains active thread footprint)")

    # 3b. Raw Win32 Thread Starting Inside the Unbacked Region
    # Mirrors shellcode entry telemetry: NtQueryInformationThread on this
    # thread resolves to flip_region, which lives in private executable
    # memory with no backing image.
    spin_thread = kernel32.CreateThread(None, 0, wintypes.LPVOID(flip_region), None, 0, None)
    if not spin_thread:
        error_code = ctypes.get_last_error()
        print(f"[-] FATAL: CreateThread failed with error {error_code}")
        kernel32.VirtualFree(flip_region, 0, MEM_RELEASE)
        kernel32.VirtualFree(base_address, 0, MEM_RELEASE)
        sys.exit(1)
    print(f"[+] Raw worker thread started at unbacked region base (handle 0x{spin_thread:X})")

    # 4. Telemetry Summary & Forensic Inspection Banner
    print("-" * 80)
    print("  VOLATILE MEMORY ARTIFACT PROFILE (EXPECTED SHADOWMEM TELEMETRY)")
    print("-" * 80)
    print(f"  * Process ID (PID)        : {pid}")
    print(f"  * Process Image Name      : {os.path.basename(sys.executable)}")
    print(f"  * Virtual Base Address    : 0x{base_address:016X}")
    print(f"  * Allocation Size         : {ALLOCATION_SIZE} bytes ({ALLOCATION_SIZE // 1024} KB)")
    print(f"  * Allocation State        : MEM_COMMIT | MEM_RESERVE (0x{allocation_flags:04X})")
    print(f"  * Memory Protection       : PAGE_EXECUTE_READWRITE (0x{protection_flags:02X}) [RWX]")
    print(f"  * Memory Type             : MEM_PRIVATE (0x00020000) [Unbacked by image file]")
    print(f"  * Active Thread Count     : {threading.active_count()} (Process main + telemetry worker)")
    print("-" * 80)
    print("  INSTRUCTIONS FOR OPERATOR:")
    print("  1. Keep this terminal RUNNING to preserve active memory pages.")
    print("  2. Open a SECOND terminal and run:")
    print("         python detecter.py")
    print("     OR launch the web dashboard / API scan:")
    print("         uvicorn app:app --reload")
    print("         Visit: http://127.0.0.1:8000/api/scan")
    print(f"  3. Verify that PID {pid} is detected with high threat score ([!] MALICIOUS).")
    print("  4. Press Ctrl + C in this terminal to gracefully exit and release memory.")
    print("=" * 80)

    # 5. Keep-Alive Loop with Interactive Heartbeat
    elapsed_seconds = 0
    try:
        while True:
            time.sleep(2.0)
            elapsed_seconds += 2
            sys.stdout.write(
                f"\r[*] [HEARTBEAT] Process holding RWX buffer at 0x{base_address:016X} "
                f"| Active: {elapsed_seconds}s | Status: Ready for forensic scan (Ctrl+C to quit)..."
            )
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n\n[*] KeyboardInterrupt (Ctrl + C) received. Initiating graceful shutdown...")

    finally:
        # 6. Clean Teardown & Resource Deallocation
        print("[*] Stopping background telemetry worker...")
        stop_event.set()
        worker.join(timeout=2.0)

        # Terminate the raw spin thread BEFORE freeing the region it lives in
        try:
            if kernel32.TerminateThread(spin_thread, 0):
                print("[*] Raw spin thread terminated.")
                kernel32.CloseHandle(spin_thread)  # close the handle after terminating
        except Exception:
            pass  # already dead or never started

        print(f"[*] Releasing virtual memory at 0x{base_address:016X} via VirtualFree...")
        # When dwFreeType is MEM_RELEASE, dwSize must be 0
        free_success = kernel32.VirtualFree(base_address, 0, MEM_RELEASE)
        if free_success:
            print("[+] Memory region decommitted and released successfully (MEM_RELEASE).")
        else:
            error_code = ctypes.get_last_error()
            print(f"[-] WARNING: VirtualFree failed with error code {error_code}.")

        try:
            kernel32.VirtualFree(flip_region, 0, MEM_RELEASE)
            print("[+] Flip region released.")
        except Exception:
            pass

        print("[+] Teardown complete. Exiting cleanly.")
        sys.exit(0)


if __name__ == "__main__":
    main()
