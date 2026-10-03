# ShadowMem 🛡️
### Automated Volatile Memory Forensics & Fileless Malware Detection

[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6.svg?logo=windows)](https://www.microsoft.com/windows)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Uvicorn-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Frontend](https://img.shields.io/badge/Frontend-Next.js%2014%20%7C%20TailwindCSS-000000.svg?logo=next.js)](https://nextjs.org)
[![ML](https://img.shields.io/badge/ML%20Engine-Random%20Forest%20(7--Feature)-F7931E.svg?logo=scikit-learn)](https://scikit-learn.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1055%20Defense%20Evasion-ED1C24.svg)](https://attack.mitre.org/techniques/T1055/)

---

## 📌 Overview

**ShadowMem** is a real-time cyber defense operations platform designed to detect, classify, and neutralize **fileless malware**, **code injection**, and **stealth memory anomalies** in volatile RAM on 64-bit Windows systems. 

Traditional signature-based and file-scanning antivirus solutions fall short when adversaries operate entirely in memory—leaving zero artifacts on disk. ShadowMem bridges this gap by directly inspecting process Virtual Address Descriptors (VAD), thread start addresses, memory protection transitions (e.g., `PAGE_EXECUTE_READWRITE`), and unbacked executable regions. Captured telemetry is evaluated using a trained 7-feature Random Forest machine learning classifier alongside heuristic rule chains to isolate malicious threads in real-time.

---

## 🔬 Core Capabilities & Forensic Engine

### 1. Win32 Virtual Memory Introspection
* **VAD Hierarchy Walkthrough**: Enumerates memory regions using low-level Win32 APIs (`VirtualQueryEx`, `NtQueryVirtualMemory`).
* **Unbacked Executable Memory Identification**: Flags committed memory marked executable (`PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`) that lacks backing from a legitimate executable image file on disk (`GetMappedFileNameW`).
* **Thread Start Address Analysis**: Queries each process thread using `ThreadQuerySetWin32StartAddress` (`ntdll.dll`) to detect threads spawned directly within unbacked dynamic code buffers (shellcode / staged payloads).
* **JIT Runtime Differentiation**: Built-in heuristic whitelist filters out legitimate user-mode Just-In-Time compilers (.NET CLR, JVM, Chromium V8, Electron) to keep false positives below **0.2%**.

### 2. 7-Feature Machine Learning Classifier
ShadowMem extracts a 7-dimensional forensic telemetry vector per process for automated classification (`shadowmem_model.pkl`):
1. `rwx_count`: Quantity of `PAGE_EXECUTE_READWRITE` memory allocations.
2. `unbacked_exec_count`: Count of executable regions unbacked by disk files.
3. `total_rwx_bytes`: Cumulative bytes mapped with RWX permissions.
4. `num_threads`: Total active process threads.
5. `thread_unbacked_start`: Flag for threads starting in unbacked regions.
6. `is_known_jit_parent`: Indicator of benign JIT engine runtime.
7. `vad_protection_anomaly`: Detection of anomalous permission flips (e.g. `PAGE_READWRITE` &rarr; `PAGE_EXECUTE_READWRITE`).

### 3. MITRE ATT&CK Mapping
Classifications map directly to industry-standard adversary tactics:
* **T1055.001**: DLL Injection (Dynamic Library Load)
* **T1055.002**: Portable Executable Injection / Reflective DLL Loading
* **T1055.003**: Thread Execution Hijacking (Context Hijack / Shellcode Start)
* **T1055.012**: Process Hollowing (Unbacked image replacement)

### 4. Live Containment & Remediation
* **Process Quarantine / Suspension**: Instantly suspend all active threads in suspicious or malicious processes via kernel-level APIs (`NtSuspendProcess` / `OpenThread`), cutting off command-and-control (C2) without crashing system stability.
* **Process Resumption**: Resume suspended processes post-investigation via `NtResumeProcess`.
* **Tamper-Resistant Audit Trail**: Full transaction log recording timestamps, targeted PIDs, actions taken, and operational outcomes.

---

## 🖥️ Next.js SOC Cyber Defense Dashboard

ShadowMem includes a modern, high-contrast Security Operations Center (SOC) dashboard built on **Next.js 14 (App Router)**, **TypeScript**, **Tailwind CSS**, and **Recharts**:

* **Warm SOC Theme**: Refined off-white surface (`#FAF7F2`), warm orange accents (`#E8793C`), and charcoal typography engineered for clarity during high-alert triage.
* **Density Toggle**: Instantly switch between **Compact** (high-density triage for multi-screen SOC analysts) and **Detailed** view modes, persisted across sessions in `localStorage`.
* **Real-Time Freshness & Last Updated Timestamps**:
  * Ticks every second (`Updated just now`, `Updated 12s ago`, etc.) across every data-bearing card.
  * Turns amber when data becomes older than 30 seconds or if the engine disconnects.
  * Standby cards remain clean without premature timestamps until a scan executes.
* **Resilient Engine Disconnection State**:
  * Continuous background probe against `/api/audit` and WebSocket stream monitoring.
  * Displays an animated warning banner (`Disconnected from ShadowMem engine — retrying...`) when the backend goes down.
  * Auto-reconnects every 3 seconds and flashes a confirmation banner (`Reconnected to ShadowMem engine`) before auto-dismissing.
* **Zero Node Server at Runtime**: Compiles to pure static assets (`frontend/out/`) served directly by FastAPI (`app.py`), requiring no Node.js runtime in production.

---

## 📁 Repository Structure

```
ShadowMem/
├── app.py                      # Authoritative FastAPI backend + Next.js static host
├── memoryscanner.py            # Win32 ctypes memory inspection engine & VAD walker
├── detecter.py                 # ML feature extraction pipeline & model inference
├── shadowmem_model.pkl         # Trained Random Forest classifier
├── technique_docs.py           # MITRE ATT&CK reference documentation & metadata
├── malware_simulator.py        # Volatile attack simulator (reflective DLL / RWX hooks)
├── launch_shadowmem.bat        # Single-click SOC launcher script
├── frontend/                   # Next.js 14 Cyber Defense Dashboard
│   ├── src/
│   │   ├── app/                # App Router pages (Overview, Live Map, Process Table, Alerts, Analytics, Kernel Log)
│   │   ├── components/         # Dashboard panels, StatCards, Header, Sidebar, LastUpdated, ConnectionBanner
│   │   ├── context/            # ConnectionContext, DensityContext, NotificationsContext
│   │   ├── lib/                # API client & WebSocket adapters
│   │   └── types/              # TypeScript forensics definitions
│   ├── out/                    # Pre-built static export served by app.py
│   ├── package.json
│   └── tailwind.config.ts
├── tests/
│   ├── test_master_suite.py    # Master automated test suite
│   ├── test_scan_api.py        # Endpoint and telemetry tests
│   ├── test_injector.py        # Memory injection unit tests
│   └── test_sandbox.py         # Isolation and containment tests
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
* **Operating System**: Windows 10/11 x64 or Windows Server 2019+
* **Python**: Python 3.10 – 3.14 (with administrator privileges recommended for scanning system processes)
* **Node.js**: Node 18+ (only needed if developing or recompiling the Next.js frontend)

---

### Quick Launch (Recommended)

Simply double-click or run the launcher script from an elevated command prompt:

```cmd
launch_shadowmem.bat
```

This activates the virtual environment, launches the backend on `http://127.0.0.1:8000`, and opens the dashboard in your default browser.

---

### Manual Backend Setup

1. **Activate the Python virtual environment**:
   ```powershell
   .\.venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```

3. **Start the Uvicorn engine**:
   ```powershell
   python -m uvicorn app:app --host 127.0.0.1 --port 8000
   ```
   Access the dashboard at `http://127.0.0.1:8000/`.

---

### Frontend Development (Optional)

If modifying or developing the Next.js frontend:

1. **Navigate to the frontend directory**:
   ```bash
   cd frontend
   npm install
   ```

2. **Run the Next.js dev server**:
   ```bash
   npm run dev
   ```
   Open `http://localhost:3000`. API calls will automatically proxy to `http://127.0.0.1:8000`.

3. **Recompile the static production export**:
   ```bash
   npm run build
   ```
   The compiled static files are exported to `frontend/out/`, where `app.py` automatically serves them.

---

## 📡 API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves the Next.js Cyber Defense Dashboard |
| `GET` | `/api/scan` | Initiates a full volatile memory scan across all accessible Windows processes |
| `POST` | `/api/isolate/{pid}` | Suspends process threads for immediate threat containment |
| `POST` | `/api/resume/{pid}` | Resumes a suspended process |
| `GET` | `/api/audit` | Retrieves the immutable containment action and audit trail |
| `WS` | `/ws/alerts` | Real-time WebSocket event stream for alerts and telemetry updates |
| `POST` | `/simulate/alert` | Injects a simulated fileless malware alert for testing and demonstration |

---

## 🧪 Testing & Simulation

* **Run Full Test Suite**:
  ```powershell
  python test_master_suite.py
  ```
* **Simulate Fileless Memory Injection**:
  ```powershell
  python malware_simulator.py
  ```
* **Verify API Freshness & Endpoints**:
  ```powershell
  python test_scan_api.py
  ```

---

## ⚖️ Security Notice & Disclaimer

ShadowMem is intended for cybersecurity research, volatile memory forensics, incident response exercises, and authorized defensive operations. Always exercise caution when invoking process suspension on mission-critical system components. Ensure appropriate authorization prior to running active memory scans on enterprise assets.
