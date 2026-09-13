"""
technique_docs.py — ShadowMem Technique Classification Lookup Table
-----------------------------------------------------------------
Static documentation for each injection technique the multi-class model
can identify.  Keyed by training subclass name; used by app.py's
evaluate_process() to attach human-readable technique information to
process records when the model classifies them as Suspicious or Malicious.

NOTE: These classifications come from a model trained ONLY on synthetic
data (see train_model.py).  Confidence scores should not be treated as
validated against real-world malware samples.  The typical-indicators
field describes feature-vector signals, not reverse-engineered shellcode.

Subclass order matches the multi-class label encoding used by
train_model.py and must stay in sync.
"""

# Canonical subclass order — indices 0-4 are benign, 5-8 are malicious.
# This list is imported by both train_model.py and app.py.
SUBCLASS_ORDER = [
    "benign_daemon",     # 0
    "benign_gui",        # 1
    "benign_jit",        # 2
    "benign_managed",    # 3
    "benign_desktop",    # 4
    "mal_reflective",    # 5
    "mal_hollow",        # 6
    "mal_shellcode",     # 7
    "mal_hijack",        # 8
]

MALICIOUS_CLASSES = SUBCLASS_ORDER[5:]   # indices 5-8

# Number of classes in the multi-class model (must match len(SUBCLASS_ORDER))
NUM_CLASSES = len(SUBCLASS_ORDER)

# Index into predict_proba output that is the first malicious class
MALICIOUS_OFFSET = 5

# ---------------------------------------------------------------------------
# Per-technique documentation
# ---------------------------------------------------------------------------
TECHNIQUE_DOCS = {
    "mal_reflective": {
        "display_name": "Reflective DLL Injection",
        "mitre_id": "T1055.001",
        "short_description": (
            "A DLL image is manually mapped into a process's virtual address "
            "space without going through the Windows loader, resulting in "
            "executable memory regions that are MEM_PRIVATE (unbacked by any "
            "file on disk).  This technique allows arbitrary code execution "
            "while evading file-based detection mechanisms."
        ),
        "typical_indicators": (
            "Moderate unbacked_exec_count (3-5 regions), small-to-moderate "
            "RWX page count, 1-2 unbacked thread starts (threads whose start "
            "address resolves into private executable memory), and a few VAD "
            "protection transitions (RW -> RX/RWX flips as the loader "
            "finalizes section protections)."
        ),
        "recommended_response": (
            "1. Suspend the process to prevent further execution.\n"
            "2. Dump all unbacked executable regions and scan for PE headers "
            "(MZ/PE signatures in MEM_PRIVATE memory).\n"
            "3. Extract any strings or API imports from the dumped regions.\n"
            "4. Cross-reference the DLL name or hash against threat intel.\n"
            "5. If confirmed malicious, terminate and escalate to the "
            "incident response team."
        ),
    },
    "mal_hollow": {
        "display_name": "Process Hollowing",
        "mitre_id": "T1055.012",
        "short_description": (
            "A legitimate process is started in a suspended state, its image "
            "is unmapped from memory, and a malicious payload is written in "
            "its place before the process is resumed.  The result is a "
            "process whose image name appears legitimate but whose executable "
            "memory is entirely private and unbacked."
        ),
        "typical_indicators": (
            "High unbacked_exec_count (5-10 regions) with moderate RWX page "
            "counts, a larger number of VAD protection transitions (5-8 "
            "flips as the payload is written and reprotected in stages), and "
            "typically 1-2 unbacked thread starts.  Total RWX bytes tend to "
            "be large (hundreds of KB to several MB) as the full PE payload "
            "is unpacked in memory."
        ),
        "recommended_response": (
            "1. Suspend the process immediately.\n"
            "2. Compare the PEB ImageBaseAddress region's protection with "
            "the expected MEM_IMAGE — MEM_PRIVATE confirms hollowing.\n"
            "3. Dump the hollowed process's memory and extract the PE.\n"
            "4. Check the original on-disk binary for comparison.\n"
            "5. Terminate and investigate the parent process chain."
        ),
    },
    "mal_shellcode": {
        "display_name": "Shellcode / C2 Beacon",
        "mitre_id": "T1620",
        "short_description": (
            "A small block of position-independent code (shellcode) is "
            "staged directly in an anonymous RWX memory region, typically "
            "committed with PAGE_EXECUTE_READWRITE from the start.  A "
            "worker thread is spawned with its start address pointing "
            "directly into this region, indicating immediate execution of "
            "the injected code."
        ),
        "typical_indicators": (
            "Small footprint: 1-3 RWX regions with low total byte count "
            "(10-200 KB), 1 unbacked thread start (the worker thread), few "
            "VAD protection transitions (often 0 — allocated RWX directly), "
            "and moderate thread count.  The combination of small allocation "
            "size with a thread pointing into it is the key signal."
        ),
        "recommended_response": (
            "1. Suspend the process to halt the beacon.\n"
            "2. Dump the RWX region contents — look for known shellcode "
            "patterns (NOP sleds, API hash resolution, network callbacks).\n"
            "3. Check network connections from the process for C2 endpoints.\n"
            "4. Extract any decoded strings or IOCs.\n"
            "5. Terminate and perform a full system sweep for persistence."
        ),
    },
    "mal_hijack": {
        "display_name": "Thread / APC Execution Hijacking",
        "mitre_id": "T1055.003",
        "short_description": (
            "An existing thread in a target process is redirected to execute "
            "injected code, either by modifying its execution context "
            "(SetThreadContext) or by queuing an Asynchronous Procedure Call "
            "(APC) that forces the thread to execute a gadget.  Because no "
            "new thread is created, this technique can evade thread-based "
            "detection heuristics."
        ),
        "typical_indicators": (
            "Very small RWX footprint (1-2 regions, 10-60 KB), low "
            "unbacked_exec_count (1-3), minimal or zero unbacked thread "
            "starts (the thread was already running), but elevated VAD "
            "protection transitions (2-4 flips as the injection stub is "
            "written and reprotected).  The combination of low thread starts "
            "with moderate VAD anomalies is the distinguishing pattern."
        ),
        "recommended_response": (
            "1. Suspend all threads in the process.\n"
            "2. Inspect each thread's start address — any pointing to "
            "unbacked private memory is suspicious.\n"
            "3. Dump the unbacked executable regions.\n"
            "4. Check for recently queued APCs.\n"
            "5. Compare thread contexts against expected call stacks."
        ),
    },
}
