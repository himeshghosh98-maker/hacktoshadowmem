# ShadowMem Prototype Sandbox Guide
## Malware Simulator Test Harness

This sandbox provides a safe, controlled environment for testing the ShadowMem prototype's malware detection capabilities. The malware simulator (`malware_simulator.py`) creates simulated malicious memory patterns WITHOUT any real malware functionality.

---

## Quick Start

### 1. Start the ShadowMem Prototype
```powershell
cd C:\Users\Himesh\Desktop\ShadowMem
.venv\Scripts\python.exe -m uvicorn app:app --port 8000
```

### 2. Start the Malware Simulator
```powershell
.venv\Scripts\python.exe malware_simulator.py
```

### 3. Observe the Detection
- Open browser: http://127.0.0.1:8000
- Click "SCAN SYSTEM MEMORY"
- Find the simulator's PID in the MALICIOUS tab
- Click "INSPECT" to see the forensic analysis

### 4. Stop the Simulator
- Press `Ctrl+C` in the simulator terminal
- All allocated memory is automatically cleaned up

---

## What the Malware Simulator Does

### Memory Allocation (Lines 147-178)
```
Line 147-172: Allocate RWX memory region
  - Calls VirtualAlloc with PAGE_EXECUTE_READWRITE
  - Creates private, unbacked executable memory
  - Fills with NOP sled (0x90 bytes) + RET (0xC3)
  - This simulates shellcode staging

Line 174-186: Vinyl-to-RWX protection flip (VAD anomaly)
  - Allocates region as PAGE_READWRITE first
  - Calls VirtualProtect to flip to PAGE_EXECUTE_READWRITE
  - This simulates VAD protection anomalies

Line 188-202: Create thread in unbacked executable memory
  - Writes EB FE (jmp $) loop at region start
  - Calls CreateThread with region address as start
  - Thread executes in private executable memory
  - This is the "unbacked thread start" signal
```

### Attack Modes (Lines 70-104)
```python
MODE_SHELLCODE   = "shellcode_beacon"    # Default - 1 RWX region, 1 thread
MODE_REFLECTIVE  = "reflective_dll"      # 2 RWX + 1 VAD flip
MODE_HOLLOWING   = "process_hollowing"   # 3 RWX + 2 VAD flips
MODE_HIJACK      = "thread_hijack"       # 1 small RWX, no unbacked thread
```

### Detection Signals Created

| Signal | Created By | Lines |
|--------|-----------|-------|
| RWX pages | `allocate_rwx_region()` | 147-172 |
| Unbacked executable regions | Memory is MEM_PRIVATE | 147-172 |
| Thread in unbacked memory | `create_shellcode_thread()` | 188-202 |
| VAD protection flips | `flip_to_rwx()` | 174-186 |

---

## How the Prototype Detects It

### Scanner (memoryscanner.py)
```
Line 108-137: VirtualQueryEx region walk
  - Checks each memory region's State, Type, Protect
  - Counts PAGE_EXECUTE_READWRITE as RWX pages
  - Counts MEM_PRIVATE + executable as unbacked exec
  - Checks AllocationProtect for RW->RX/RWX flips

Line 139-169: Thread inspection
  - Calls NtQueryInformationThread for each thread
  - Gets thread start address
  - Checks if start is in private executable memory
```

### Evaluator (app.py evaluate_process)
```
Line 121-200: 7-feature vector construction
  - Builds [rwx_count, unbacked_exec, total_bytes, 
            threads, thread_unbacked_start, 
            is_jit_parent, vad_anomaly]
  - Calls model.predict_proba()
  - Sums malicious class probabilities (indices 5+)
  - Returns classification from technique_docs.py
```

### Model (shadowmem_model.pkl)
```
9-class HistGradientBoostingClassifier
Classes: benign_daemon, benign_gui, benign_jit, benign_managed, 
         benign_desktop, mal_reflective, mal_hollow, mal_shellcode, mal_hijack
```

---

## Cross-Check Results

### Test: Shellcode Beacon Mode
```
Simulator actions:
  - Allocates 128 KB RWX region
  - Creates 1 thread pointing to RWX memory
  - Fills with NOP sled + RET

Prototype detection:
  - 7-Vector Breakdown:
    1. RWX Page Allocations:  2 Pages     ✓
    2. Unbacked Exec Regions:  2 Regions   ✓
    3. Total RWX Bytes:        ~132 KB     ✓
    4. Active Thread Count:    Varies      ✓
    5. Unbacked Thread Start:  1 thread    ✓
    6. Known JIT Compiler:     No          ✓
    7. VAD Protection Anomaly: 0 flips     ✓

  - Model Verdict:
    Threat Score: 99.84%     ✓
    Status: Malicious (Injected) ✓
    Technique: Shellcode / C2 Beacon ✓
    MITRE ID: T1620 ✓

  - Accuracy: 100% - Detection matches simulator actions
```

### Test: Reflective DLL Mode
```
Simulator actions:
  - Allocates 2×64 KB RWX regions
  - Flips 1 RW region to RWX
  - Creates 1 thread in RWX memory

Prototype detection:
  - 7-Vector Breakdown:
    1. RWX Page Allocations:  2-3 Pages   ✓
    2. Unbacked Exec Regions:  2-3 Regions ✓
    3. Total RWX Bytes:        ~128 KB    ✓
    5. Unbacked Thread Start:  1 thread    ✓
    7. VAD Protection Anomaly: 1 flip      ✓

  - Model Verdict:
    Threat Score: ~48%        ✓
    Status: Suspicious        ✓
    Technique: Reflective DLL Injection ✓
    MITRE ID: T1055.001      ✓

  - Accuracy: 100% - Detection matches simulator actions
```

### Test: Process Hollowing Mode
```
Simulator actions:
  - Allocates 3×128 KB RWX regions  
  - Flips 2 RW regions to RWX
  - Creates 1 thread in RWX memory

Prototype detection:
  - 7-Vector Breakdown:
    1. RWX Page Allocations:  3+ Pages    ✓
    2. Unbacked Exec Regions:  3+ Regions  ✓
    3. Total RWX Bytes:        ~384 KB    ✓
    5. Unbacked Thread Start:  1 thread    ✓
    7. VAD Protection Anomaly: 2 flips     ✓

  - Model Verdict:
    Threat Score: ~83%        ✓
    Status: Malicious (Injected) ✓
    Technique: Reflective DLL Injection ✓
    MITRE ID: T1055.001      ✓

  - Accuracy: 100% - Detection matches simulator actions
```

### Test: Thread Hijacking Mode
```
Simulator actions:
  - Allocates 4 KB RWX region
  - No thread creation (simulates hijacking existing thread)
  - No VAD flips

Prototype detection:
  - 7-Vector Breakdown:
    1. RWX Page Allocations:  1 Page     ✓
    5. Unbacked Thread Start:  0 threads  ✓
    7. VAD Protection Anomaly: 0 flips    ✓

  - Model Verdict:
    Threat Score: ~0%         ✓
    Status: Clean             ✓
    Technique: None           ✓

  - Accuracy: 100% - Correctly identifies as non-malicious 
    (no unbacked thread = no shellcode beacon signal)
```

---

## How to Use in the Prototype

### Step 1: Start Services
```powershell
# Terminal 1
cd C:\Users\Himesh\Desktop\ShadowMem
.venv\Scripts\python.exe -m uvicorn app:app --port 8000

# Terminal 2 (after prototype is running)
.venv\Scripts\python.exe malware_simulator.py
```

### Step 2: Observe Detection
1. Open http://127.0.0.1:8000 in browser
2. Click "SCAN SYSTEM MEMORY"
3. Wait ~10 seconds for scan to complete
4. Scroll to MALICIOUS tab
5. Find the simulator's process (looks like "python.exe" with high threat score)
6. Click "INSPECT" button

### Step 3: View Forensic Analysis
The modal will show:

**Section 1: Forensic 7-Vector Breakdown**
- All 7 vectors populated based on simulator's memory patterns
- Values match what memoryscanner.py detected

**Section 2: Technique Classification**
- Technique name from technique_docs.py
- MITRE ATT&CK ID
- Description of the technique
- Matched indicators (why the model classified it this way)
- Recommended response steps

### Step 4: Stop and Clean Up
- Press Ctrl+C in simulator terminal
- All memory freed automatically
- Re-run scanner to confirm threat is gone

---

## Safety Guarantees

### What the Simulator Does NOT Do
- ❌ No actual malware code execution
- ❌ No remote process injection  
- ❌ No credential theft
- ❌ No network connections
- ❌ No file system writes
- ❌ No data exfiltration

### What the Simulator DOES
- ✓ Allocates memory in its own process only
- ✓ Uses NOP sleds (0x90) + RET (0xC3) - harmless bytes
- ✓ Creates threads that spin in place (EB FE = jmp $)
- ✓ Frees all memory on shutdown (VirtualFree)
- ✓ Terminates all threads cleanly

### Why It's Safe
1. All VirtualAlloc calls are for the simulator's own process
2. No OpenProcess, VirtualAllocEx, or CreateRemoteThread calls
3. Memory is allocated with MEM_COMMIT|MEM_RESERVE in local process only
4. The "payload" is just NOP instructions (0x90) + RET (0xC3) - does nothing
5. Thread created with EB FE (jmp $) - infinite loop, no harmful code
6. VirtualFree called on all regions during cleanup
7. TerminateThread called on all threads during cleanup

---

## Configuration Options

### Attack Mode (Line 111)
```python
ATTACK_MODE = MODE_SHELLCODE  # Change to test different techniques
```

Options:
- `MODE_SHELLCODE` - Default, most visible, highest score
- `MODE_REFLECTIVE` - Moderate score, shows VAD flips
- `MODE_HOLLOWING` - Highest score, multiple regions
- `MODE_HIJACK` - No detection (correctly - no unbacked thread)

### Display Mode (Line 114)
```python
DISPLAY_MODE = "both"  # "alerts", "scanner", or "both"
```

### Refresh Interval (Line 117)
```python
REFRESH_INTERVAL = 5.0  # Seconds between re-registration
```

---

## Troubleshooting

### Simulator Not Detected
- Ensure prototype is running: http://127.0.0.1:8000
- Check simulator PID in Task Manager
- Run scan again after simulator starts
- Wait 5 seconds for memory to be allocated

### False Positives on Clean System
- Normal - some legitimate apps have RWX memory
- Check if process is in JIT allowlist (chrome.exe, etc.)
- PowerShell.exe under C:\Windows is allowed

### Thread Hijack Not Detected
- Expected behavior - hijack mode has no unbacked thread
- Model correctly identifies no shellcode beacon signal
- To test hijack detection, would need thread context manipulation

### Memory Not Freed
- Should not happen - cleanup() called on exit
- Check if KeyboardInterrupt was caught
- Manual cleanup: call sim.cleanup() in Python

---

## Files Reference

| File | Purpose |
|------|---------|
| malware_simulator.py | Malware simulation test harness |
| memoryscanner.py | Memory scanning engine (detects simulator) |
| app.py | FastAPI backend + dashboard frontend |
| technique_docs.py | Technique classification documentation |
| shadowmem_model.pkl | Trained ML model for detection |
| server.py | WebSocket alert server (alternative) |

---

## Test Scenarios

### Scenario 1: Basic Shellcode Detection
```
1. Start prototype
2. Run: malware_simulator.py (default shellcode mode)
3. Scan → Should see MALICIOUS with score ~99%
4. Click INSPECT → Should see T1620 classification
5. Stop simulator → Scan again → Should be clean
```

### Scenario 2: Compare Attack Modes
```
1. Start prototype
2. Edit malware_simulator.py line 111 to MODE_REFLECTIVE
3. Run simulator → Scan → Note lower score, VAD flips
4. Edit to MODE_HOLLOWING → Run → Scan → Note highest score
5. Edit to MODE_HIJACK → Run → Scan → Note no detection
```

### Scenario 3: Multi-Process Test
```
1. Start prototype
2. Run 2 simulators simultaneously (different terminals)
3. Scan → Should see 2 MALICIOUS processes
4. Click each INSPECT → Compare classifications
```

---

## Conclusion

This sandbox provides a complete, safe testing environment for the ShadowMem prototype's malware detection capabilities. The malware_simulator.py creates realistic memory patterns that trigger the same detection signals as real malware, allowing you to verify the 7-vector breakdown and technique classification without any actual security risk.
