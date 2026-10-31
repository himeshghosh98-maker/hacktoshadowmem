# ShadowMem Comprehensive Repository Audit & Technical Status Report

**Document Date:** October 30, 2026  
**Auditor:** Automated Security Intelligence & System Forensics Auditor  
**Repository:** ShadowMem (`c:\Users\Himesh\Desktop\ShadowMem`)  
**Audit Mode:** Read-Only Source Audit & Live Verification  

---

## Executive Summary

ShadowMem is a specialized volatile memory forensics and fileless malware detection platform for Windows environments. It bridges low-level Win32 memory traversal (`VirtualQueryEx`, `NtQueryInformationThread`, `SuspendThread`) with a trained 9-class scikit-learn machine learning classifier (`HistGradientBoostingClassifier`) to detect in-memory threats such as shellcode beacons (T1620), reflective DLL injection (T1055.001), and process hollowing (T1055.012).

This comprehensive audit evaluates the entire repository as it stands today. All claims are grounded in live command executions, verified test suites, file paths, and line numbers.

---

## 1. Repository Map

### 1.1 Folder Tree Architecture

```
ShadowMem/
├── core/                                # Central configuration and structured logging
│   ├── __init__.py                      # Package initialization (exports settings, logger)
│   ├── config.py                        # Pydantic-settings BaseSettings singleton (env + defaults)
│   └── logging.py                       # Python logging configuration (structured console formatter)
├── routers/                             # FastAPI API route modules
│   ├── __init__.py                      # Assembles v1_router (/api/v1) and compat_router
│   ├── alerts.py                        # /api/v1/simulate/alert and WebSocket /ws/alerts
│   ├── containment.py                   # /api/v1/isolate/{pid}, /api/v1/resume/{pid}, /api/v1/audit
│   ├── forensics.py                     # /api/v1/scan and legacy /api/scan
│   ├── sandbox.py                       # /api/v1/sandbox/* (health, submit, status, jobs)
│   └── supply_chain.py                  # /api/v1/supply-chain/* (health, scan/process, scan/path)
├── schemas/                             # Pydantic V2 data contracts and request/response models
│   ├── __init__.py                      # Re-exports all schemas
│   ├── alerts.py                        # AlertFrame, MemoryMapFrame, SimulateAlertRequest/Response
│   ├── containment.py                   # IsolateRequest, ContainmentResponse, AuditResponse
│   ├── forensics.py                     # ScanResponse, ScanSummary, ProcessEntry, UnbackedRegion
│   ├── sandbox.py                       # SandboxSubmissionRequest, SandboxExecutionResult, Health
│   └── supply_chain.py                  # SupplyChainScanRequest, Response, ModuleIntegrityFinding
├── services/                            # Core domain logic and system integration services
│   ├── __init__.py                      # Package initialization
│   ├── alerts.py                        # WebSocket ConnectionManager, background scan ticker, memory-map builder
│   ├── containment.py                   # Win32 OpenProcess/OpenThread thread suspension and audit trail
│   ├── forensics.py                     # Model inference, process feature alignment, scan-lock coordinator
│   ├── sandbox.py                       # WSL2 / Docker capability inspection and mock execution tracking
│   └── supply_chain.py                  # Process module enumeration via psutil and PE Authenticode verification
├── frontend/                            # Next.js 14 App Router dashboard
│   ├── package.json                     # Dependencies (Next 14.2.35, React 18, Recharts, Lucide)
│   ├── next.config.mjs                  # Static export config ('export') and dev-server proxy rewrites
│   ├── tailwind.config.ts               # Theme definitions and color tokens
│   ├── out/                             # Prerendered static production export (served by app.py)
│   └── src/
│       ├── app/                         # App Router page routes
│       │   ├── page.tsx                 # SOC Overview dashboard with HUD, metrics, and dossier modal
│       │   ├── alerts/page.tsx          # Real-time and simulated alert triage view
│       │   ├── analytics/page.tsx       # Recharts visualizations (pie charts, trend areas, histograms)
│       │   ├── kernel-log/page.tsx      # Terminal-style telemetry log viewer with filter & export
│       │   ├── live-map/page.tsx        # HTML5 Canvas radial memory map visualizer
│       │   └── process-table/page.tsx   # Sortable, filterable process grid with dossier integration
│       ├── components/                  # Shared UI components (Header, Sidebar, DossierModal, etc.)
│       ├── context/                     # React Context providers (ConnectionContext, DensityContext, NotificationsContext)
│       ├── data/                        # Static mock fallback dataset (mockForensics.ts)
│       ├── lib/                         # API client layer (api.ts - fetchScan, isolateProcess, WebSocket)
│       └── types/                       # TypeScript interfaces for forensic telemetry and payloads
├── templates/                           # Standalone HTML templates
│   └── fallback_dashboard.html          # Embedded Tailwind dashboard served if frontend/out is absent
├── tests/                               # Verification test suites
│   ├── mocks/
│   │   └── server.py                    # Standalone test mock server (bound to port 8082)
│   ├── test_api_v1_schemas.py           # Pydantic schema validation and OpenAPI spec checks
│   ├── test_config_settings.py          # Settings precedence and environment parsing verification
│   ├── test_layered_architecture.py     # Clean separation and service layer unit tests
│   └── test_step5_integrations.py       # Sandbox & Supply Chain router/service integration tests
├── app.py                               # Single authoritative FastAPI bootstrap and layer coordinator
├── config.py                            # Backward-compatibility alias re-exporting core.config.settings
├── detecter.py                          # Standalone CLI memory inspection utility
├── memoryscanner.py                     # Low-level Win32 VirtualQueryEx memory traversal engine
├── malware_simulator.py                 # Multi-mode in-memory attack simulation test fixture
├── technique_docs.py                    # MITRE ATT&CK technique classifications and documentation
├── test_fixes.py                        # Smoke test verifying server scan, isolate, and HTML endpoints
├── test_injector.py                     # Synthetic self-contained RWX / unbacked thread injection harness
├── test_master_suite.py                 # 6-phase master end-to-end integration and verification suite
├── test_sandbox.py                      # Multi-attack sandbox classifier unit test runner
├── train_model.py                       # 9-class HistGradientBoostingClassifier training pipeline
├── trigger_test_event.py                # Standalone simulation alert trigger script
└── requirements.txt                     # Python package dependencies
```

---

### 1.2 Module Descriptions

| Module / Component | Primary Responsibility | Key Win32 / Framework APIs Used |
| :--- | :--- | :--- |
| `app.py` | FastAPI application bootstrap, CORS middleware, mounting `/api/v1` & compat routers, serving Next.js static export from `frontend/out`. | FastAPI, Starlette StaticFiles, Uvicorn |
| `core/config.py` | Centralized typed configuration loading from `.env` and `SHADOWMEM_*` environment variables. | Pydantic V2, `pydantic-settings.BaseSettings` |
| `core/logging.py` | Structured, formatted logging across all backend services. | Standard library `logging` |
| `services/forensics.py` | Evaluates process feature vectors using `shadowmem_model.pkl` and serializes scans under `_scan_lock`. | NumPy, Scikit-learn, `threading.Lock` |
| `services/containment.py`| Suspends/resumes process threads; maintains in-memory audit trail; protects system PIDs. | Win32 `OpenProcess`, `OpenThread`, `SuspendThread`, `ResumeThread`, `CloseHandle` |
| `services/alerts.py` | Broadcasts alerts and memory maps over WebSockets; manages background periodic memory scan ticker. | `asyncio`, FastAPI WebSockets |
| `services/supply_chain.py`| Inspects loaded modules for live processes or directories; parses Authenticode signatures and SHA-256 hashes. | `psutil`, `pefile`, `hashlib` |
| `services/sandbox.py` | Validates host WSL2/Docker daemon readiness; tracks sandbox detonation jobs. | `subprocess`, `shutil`, `uuid` |
| `memoryscanner.py` | Walks user-mode virtual memory spaces; identifies committed `MEM_PRIVATE` executable regions and unbacked threads. | Win32 `VirtualQueryEx`, `NtQueryInformationThread` |
| `frontend/src/lib/api.ts`| Client-side communication layer for REST calls (`/api/v1/*`) and WebSocket feed (`/api/v1/ws/alerts`). | Browser Fetch API, standard WebSocket API |

---

### 1.3 Line Counts of the Largest Files

The line counts of the top 25 non-vendor source files were computed dynamically via Python (`sum(1 for _ in fp)`):

```
 2476  templates\fallback_dashboard.html
 1456  index.html
  856  build_backend_audit_pdf.py
  776  build_step3_closure_pdf.py
  711  build_frontend_audit_pdf.py
  683  make_error_report_pdf.py
  676  build_step5_verification_pdf.py
  634  frontend\src\app\live-map\page.tsx
  616  train_model.py
  613  build_config_verification_pdf.py
  606  make_pdf.py
  599  frontend\src\app\process-table\page.tsx
  592  frontend\src\app\analytics\page.tsx
  580  build_full_analysis_pdf.py
  513  malware_simulator.py
  470  frontend\src\app\page.tsx
  446  build_step1_verification_pdf.py
  374  services\containment.py
  374  README_sandbox.md
  347  tests\test_api_v1_schemas.py
  338  frontend\src\app\alerts\page.tsx
  331  frontend\src\app\kernel-log\page.tsx
  328  test_injector.py
  312  frontend\src\lib\api.ts
  312  frontend\src\components\dashboard\AnalyticsRow.tsx
```

---

## 2. How to Run

### 2.1 Clean-Clone Startup Commands

#### Backend:
1. Create and activate virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
2. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
3. Start authoritative server:
   ```powershell
   python -m uvicorn app:app --host 127.0.0.1 --port 8000
   ```
   *(Alternatively, run `launch_shadowmem.bat`)*

#### Frontend:
1. Change into frontend directory and install dependencies:
   ```powershell
   cd frontend
   npm.cmd install
   ```
   *(Note: On Windows PowerShell, execute `npm.cmd` rather than `npm` if script execution policies block `npm.ps1`)*
2. Start development server (dev mode with hot reloading on port 3000):
   ```powershell
   npm.cmd run dev
   ```
3. Or build production static export (served by FastAPI on port 8000):
   ```powershell
   npm.cmd run build
   ```

---

### 2.2 Actual Startup Verification & Real Output

#### A. Backend Execution
- **Command:** `.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000`
- **Port:** `8000`
- **Output:**
```
INFO:     Started server process [16164]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```
- **Result:** Successfully started without errors or warnings.

#### B. Frontend Development Server Execution
- **Command:** `npm.cmd run dev` (in `frontend/`)
- **Port:** `3000`
- **Output:**
```
> frontend@0.1.0 dev
> next dev

  ▲ Next.js 14.2.35
  - Local:        http://localhost:3000

 ✓ Starting...
 ✓ Ready in 2.4s
```
- **Result:** Successfully compiled and ready in 2.4s.

#### C. Frontend Production Build Execution
- **Command:** `npm.cmd run build` (in `frontend/`)
- **Output:**
```
> frontend@0.1.0 build
> next build

  ▲ Next.js 14.2.35

   Creating an optimized production build ...
 ✓ Compiled successfully
   Linting and checking validity of types ...
   Collecting page data ...
   Generating static pages (0/10) ...
   Generating static pages (2/10) 
   Generating static pages (4/10) 
   Generating static pages (7/10) 
 ✓ Generating static pages (10/10)
   Finalizing page optimization ...
   Collecting build traces ...

Route (app)                              Size     First Load JS
┌ ○ /                                    12.7 kB         218 kB
├ ○ /_not-found                          873 B          88.3 kB
├ ○ /alerts                              5.03 kB        98.3 kB
├ ○ /analytics                           15.6 kB         215 kB
├ ○ /kernel-log                          7.78 kB        95.2 kB
├ ○ /live-map                            4.69 kB          98 kB
└ ○ /process-table                       5.64 kB          99 kB
+ First Load JS shared by all            87.5 kB
  ├ chunks/117-e6b781bd43e652ac.js       31.9 kB
  ├ chunks/fd9d1056-307a36020502e7d7.js  53.6 kB
  └ other shared chunks (total)          1.95 kB

○  (Static)  prerendered as static content
```
- **Result:** Zero compile or type errors. Successfully populated `frontend/out`.

---

## 3. Backend Endpoint Inventory

Every versioned `/api/v1` endpoint and WebSocket route was inventoried and queried live against `http://127.0.0.1:8000`.

| Method | Path | Request Schema | Response Schema | Live Status | Live Real Output / Summary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/scan` | None | `ScanResponse` | **200 OK** | `{"summary": {"total_scanned": 129, "anomalies_detected": 0, "malicious_count": 0, "suspicious_count": 0, "jit_engine_count": 28, "clean_count": 101, "system_posture": "Protected", "model_loaded": true}, "processes": [...]}` |
| `POST` | `/api/v1/isolate/{pid}` | `IsolateRequest` (`reason: Optional[str]`) | `ContainmentResponse` | **404 Not Found** *(test PID 99999)* / **200 OK** *(live PID)* | `{"success": false, "error": "Process 'pid:99999' (PID 99999) no longer exists.", "action": "suspended"}` |
| `POST` | `/api/v1/resume/{pid}` | None | `ContainmentResponse` | **404 Not Found** *(test PID 99999)* / **200 OK** *(live PID)* | `{"success": false, "error": "Process 'pid:99999' (PID 99999) no longer exists.", "action": "resumed"}` |
| `GET` | `/api/v1/audit` | None | `AuditResponse` | **200 OK** | `{"actions": [...]}` *(contains complete list of isolate/resume actions)* |
| `POST` | `/api/v1/simulate/alert`| `SimulateAlertRequest` (`scenario`, `severity`) | `SimulateAlertResponse`| **200 OK** | `{"status": "broadcast", "alert_id": "2ede7d57-7c30-48e5-9eb1-a5843a8f54f0", "scenario": "cobalt_strike_reflective_injection", "severity": "critical"}` |
| `GET` | `/api/v1/sandbox/health`| None | `SandboxHealthResponse`| **200 OK** | `{"enabled": false, "wsl_distro": "Ubuntu", "wsl_available": true, "docker_ready": false, "message": "Docker sandbox is disabled in configuration..."}` |
| `POST` | `/api/v1/sandbox/submit`| `SandboxSubmissionRequest` | `SandboxExecutionResult`| **200 OK** | `{"job_id": "9fdb43a5-...", "status": "disabled", "sample_name": "test_sample.exe", "error": "Sandbox execution is currently disabled..."}` |
| `GET` | `/api/v1/sandbox/status/{id}`| `job_id: str` (path) | `SandboxExecutionResult`| **404 Not Found** *(invalid ID)* | `{"detail": "Sandbox job 'fake-job-id' not found."}` |
| `GET` | `/api/v1/sandbox/jobs` | None | `List[SandboxExecutionResult]` | **200 OK** | `[]` *(in-memory job store)* |
| `GET` | `/api/v1/supply-chain/health` | None | `SupplyChainHealthResponse` | **200 OK** | `{"enabled": true, "pefile_available": true, "message": "Supply chain and module integrity scanner is active."}` |
| `POST` | `/api/v1/supply-chain/scan/process/{pid}` | `pid: int` (path) | `SupplyChainScanResponse` | **200 OK** | PID 4: `{"target": "System (PID 4)", "total_modules_scanned": 0, "posture": "Protected", "findings": []}` |
| `POST` | `/api/v1/supply-chain/scan/path` | `SupplyChainScanRequest` (`target_path`) | `SupplyChainScanResponse` | **200 OK** | `{"target": ".", "total_modules_scanned": 0, "unsigned_count": 0, "suspicious_count": 0, "posture": "Protected", "findings": []}` |
| `WS` | `/api/v1/ws/alerts` | Handshake | `AlertFrame` & `MemoryMapFrame` | **Connected (101)** | Frame 1: `{"type": "alert", "event_id": "welcome-0000", ...}`<br/>Frame 2: `{"type": "memory_map", "blocks": [...]}` |

---

## 4. Frontend-to-Backend Contract Check

Inspection of all frontend network calls in `frontend/src/lib/api.ts` and `frontend/src/context/ConnectionContext.tsx` reveals:

### 4.1 Implemented Endpoint Contract Status

1. **`fetchScan()` (`frontend/src/lib/api.ts:71`)**  
   - Target: `GET /api/v1/scan`
   - Contract match: **MATCHES**. Correctly unmarshals into `ScanResponse` (`summary` and `processes`).
2. **`isolateProcess()` (`frontend/src/lib/api.ts:105`)**  
   - Target: `POST /api/v1/isolate/${pid}` with `{ "reason": reason }` body
   - Contract match: **MATCHES**. Sends JSON body complying with `IsolateRequest` schema and returns `IsolateResponse`.
3. **`resumeProcess()` (`frontend/src/lib/api.ts:130`)**  
   - Target: `POST /api/v1/resume/${pid}`
   - Contract match: **MATCHES**. Complies with `POST /api/v1/resume/{pid}` and parses `IsolateResponse`.
4. **`fetchAudit()` (`frontend/src/lib/api.ts:153`)**  
   - Target: `GET /api/v1/audit`
   - Contract match: **MATCHES**. Correctly decodes `AuditResponse` containing `actions[]`.
5. **`simulateAlert()` (`frontend/src/lib/api.ts:180`)**  
   - Target: `POST /api/v1/simulate/alert` with `{ "scenario": ..., "severity": ... }` body
   - Contract match: **MATCHES**. Complies with `SimulateAlertRequest` and `SimulateAlertResponse`.
6. **`connectAlertsWebSocket()` (`frontend/src/lib/api.ts:230`)**  
   - Target: `ws(s)://${host}/api/v1/ws/alerts`
   - Contract match: **MATCHES**. Connects to backend WebSocket.

### 4.2 Legacy and Unversioned Calls Identified

- **`frontend/next.config.mjs:21-23`**:
  ```javascript
  {
    source: '/simulate/:path*',
    destination: 'http://127.0.0.1:8000/simulate/:path*',
  }
  ```
  *Flag:* Proxies unversioned `/simulate/*` to the compatibility endpoint instead of exclusively proxying `/api/*`.
- **`frontend/src/data/mockForensics.ts:45`**:
  ```typescript
  remediation: "Execute user-mode thread suspension immediately via POST /api/isolate/4920.",
  ```
  *Flag:* Legacy unversioned URL referenced in documentation string.

### 4.3 Missing Frontend Contracts

The Next.js frontend has **no integration** for the following backend endpoints:
- `/api/v1/sandbox/health`
- `/api/v1/sandbox/submit`
- `/api/v1/sandbox/status/{job_id}`
- `/api/v1/sandbox/jobs`
- `/api/v1/supply-chain/health`
- `/api/v1/supply-chain/scan/process/{pid}`
- `/api/v1/supply-chain/scan/path`

*Impact:* The sandbox and supply chain features are completely inaccessible to users using the web dashboard.

---

## 5. Bug Register

### 5.1 Verification of ERR-01 Through ERR-09

| Bug ID | Severity | Description | Current Status | Empirical Proof / Verification Details |
| :--- | :--- | :--- | :--- | :--- |
| **ERR-01** | CRITICAL | Invalid `wintypes.INVALID_HANDLE_VALUE` & `NTSTATUS` AttributeError Crash + Handle Leaks | **FIXED** | In `services/containment.py:19`, `INVALID_HANDLE_VALUE = -1` is explicitly defined. In `memoryscanner.py:73`, `ntdll.NtQueryInformationThread.restype = ctypes.c_long`. Tested via `test_fixes.py` and `test_master_suite.py` Phase 4 with 0 crashes. |
| **ERR-02** | CRITICAL | TypeError on Thread Enumeration (`for tid in proc.num_threads():`) | **FIXED** | In `services/containment.py:81`, enumeration iterates over `proc.threads()` (`for td in proc.threads():`), while `features["num_threads"] = proc.num_threads()` in `memoryscanner.py:127`. Tested via Phase 4 suspension of 6 threads. |
| **ERR-03** | HIGH | Process Containment Button UI Lockout (`pointer-events-none`) | **FIXED** | In `templates/fallback_dashboard.html:1500, 1509, 1555`, `pointer-events-none` is cleared on isolate/resume transitions. In Next.js `ProcessDossierModal.tsx:232`, UI lockout is handled via `disabled={isIsolating}`. |
| **ERR-04** | HIGH | Variable Shadowing, AttributeError & Thread Count Inflation in `test_sandbox.py` | **FIXED** | In `test_sandbox.py:15-17`, OpenMP/BLAS thread accumulation is capped (`OMP_NUM_THREADS = '1'`). In lines 246-259, shadowing was eliminated (`passed_count` vs `test_status`). Verified: `test_sandbox.py` executed 6/6 test suites with 100% passing. |
| **ERR-05** | MEDIUM | Premature Socket Timeout on Full Memory Scans (`timeout=30`) | **FIXED** | `timeout=60` configured in `test_fixes.py:6` and `malware_simulator.py:383`. Verified: `test_fixes.py` completed full 129-process memory scan in 21 seconds without socket timeout. |
| **ERR-06** | MEDIUM | Scan Flooding (5s Interval) & Missing `/simulate/alert` Route | **FIXED** | In `malware_simulator.py:118`, `REFRESH_INTERVAL = 45.0` (raised from 5.0). In lines 106-111, `SIMULATE_SCENARIO_BY_MODE` maps modes to valid backend scenarios. Verified: `trigger_test_event.py` returned HTTP 200 `status: broadcast`. |
| **ERR-07** | MEDIUM | Windows Console UnicodeEncodeError on Checkmark Character (`\u2713` / ✓) | **FIXED** | Replaced all instances of `\u2713` with ASCII `[+]` and `[!]` in `detecter.py:110-112`. Verified: `detecter.py` executed directly in CP1252 PowerShell console without encoding crashes. |
| **ERR-08** | LOW | Kernel Thread Handle Leak in `test_injector.py` | **FIXED** | In `test_injector.py:304`, `kernel32.CloseHandle(spin_thread)` is called immediately in `finally:` block. Verified: Phase 3 of `test_master_suite.py` started and terminated injector cleanly. |
| **ERR-09** | MEDIUM | Dual Divergent Server Architectures (`server.py` vs `app.py`) | **FIXED** | `server.py` retired from root and relocated to `tests/mocks/server.py` on mock port 8082. `app.py` is the single authoritative server on port 8000. Verified: `launch_shadowmem.bat` and `test_master_suite.py` run against `app.py`. |

---

### 5.2 New Bugs Discovered

#### NEW-01 [HIGH] Frontend Memory Map WebSocket Frames Silently Discarded
- **File & Line:** `frontend/src/lib/api.ts:245`
- **Reproduction Steps:**
  1. Start backend and frontend. Connect to WebSocket stream at `ws://127.0.0.1:8000/api/v1/ws/alerts`.
  2. Backend immediately emits an initial `memory_map` frame (`services/alerts.py:42`) containing block allocations.
  3. Inspect `frontend/src/lib/api.ts` line 245:
     ```typescript
     if (payload.type && payload.type !== "alert") return;
     ```
  4. The client unconditionally discards every incoming `memory_map` payload.
- **Impact:** Live process memory visualization on the frontend remains unpopulated from the WebSocket stream.
- **Suggested Fix:** Add an `onMemoryMap` callback to `connectAlertsWebSocket` or emit a custom `shadowmem:memory_map` event to route memory blocks to the live-map canvas.

#### NEW-02 [HIGH] Invalid and Insecure CORS Middleware Configuration
- **File & Line:** `core/config.py:103-105`, `app.py:46-51`
- **Reproduction Steps:**
  1. Inspect `core/config.py`:
     ```python
     cors_origins: Annotated[List[str], NoDecode] = Field(default_factory=lambda: ["*"])
     ```
  2. Inspect `app.py`:
     ```python
     app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True, ...)
     ```
  3. Attempting to make a credentialed cross-origin request from a browser causes browsers to reject the response per W3C CORS specification (wildcard `*` cannot be used with `allow_credentials=True`). Furthermore, allowing wildcard origins permits any malicious website opened in an analyst's browser to execute requests against `http://127.0.0.1:8000`.
- **Impact:** Potential drive-by process isolation (CSRF/DoS) and standards violation.
- **Suggested Fix:** In `core/config.py`, change default `cors_origins` to `["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000", "http://127.0.0.1:8000"]`, and explicitly disallow `*` when `allow_credentials=True`.

#### NEW-03 [HIGH] Unauthenticated Process Containment Endpoints
- **File & Line:** `routers/containment.py:27-62`
- **Reproduction Steps:**
  1. From any terminal or local script, send:
     ```powershell
     Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/isolate/<target_pid>" -Method POST
     ```
  2. Observe that any user-mode target process is immediately suspended without any authentication header, token, or session verification.
- **Impact:** Any unauthenticated local software or compromised user process can abuse ShadowMem's containment API to freeze operating system utilities, developer tools, or security software.
- **Suggested Fix:** Introduce API key or session token verification middleware on all containment mutation routes (`/api/v1/isolate` and `/api/v1/resume`).

#### NEW-04 [HIGH] Fragmented Frontend State Across Dashboard Pages
- **File & Line:** `frontend/src/app/page.tsx:37`, `frontend/src/app/process-table/page.tsx:31`, `frontend/src/app/live-map/page.tsx:37`, `frontend/src/app/analytics/page.tsx:38`
- **Reproduction Steps:**
  1. Open Overview page (`/`) and click "Run Memory Audit". Wait 20 seconds for all 129 processes to populate.
  2. Click "Process Table" in the left navigation sidebar.
  3. Observe that the process table is completely blank and displays 0 processes.
  4. The user is forced to re-run the 20-second scan on every page because state is managed strictly with local `useState<ProcessEntry[]>([])`.
- **Impact:** Substandard user experience and excessive CPU load due to duplicate 20-second full memory scans.
- **Suggested Fix:** Lift `processes`, `summary`, `lastScanTime`, and `runScan` into a global `ForensicsContext` provider in `frontend/src/context/ForensicsContext.tsx`.

#### NEW-05 [MEDIUM] Unrestricted Arbitrary Directory Scan in Supply Chain Service
- **File & Line:** `services/supply_chain.py:160-172`, `routers/supply_chain.py:59-75`
- **Reproduction Steps:**
  1. Send an HTTP POST request to `/api/v1/supply-chain/scan/path` with body `{"target_path": "C:\\Windows\\System32"}`.
  2. The server accepts and parses arbitrary host paths using `Path(dir_path)` without directory boundary validation or path traversal restrictions.
- **Impact:** Arbitrary directory scanning and file enumeration across the Windows host.
- **Suggested Fix:** Sanitize input path and enforce that `target_path` is restricted to authorized project roots or analysis folders.

#### NEW-06 [MEDIUM] Insecure Pickle Deserialization for ML Model Loading
- **File & Line:** `services/forensics.py:69-70`, `detecter.py:26-27`
- **Reproduction Steps:**
  1. Inspect `services/forensics.py`:
     ```python
     with open(model_path, "rb") as f:
         _model = pickle.load(f)
     ```
  2. `pickle.load()` deserializes arbitrary Python bytecode without cryptographic signature or hash verification.
- **Impact:** If an adversary modifies or replaces `shadowmem_model.pkl` on disk, arbitrary remote code execution is achieved upon server startup or model load.
- **Suggested Fix:** Verify the SHA-256 checksum of `shadowmem_model.pkl` against a known digest before loading, or migrate the model to ONNX or SafeTensors.

#### NEW-07 [LOW] Hardcoded Fake Ring-0 Kernel Telemetry in Frontend
- **File & Line:** `frontend/src/app/kernel-log/page.tsx:26-61`, `frontend/src/app/page.tsx:40-61`
- **Reproduction Steps:**
  1. Open the Kernel Log page (`/kernel-log`).
  2. Observe default logs claiming: `"VAD memory auditing filter driver initialized in Ring-0."` and `"NtQueryVirtualMemory handles bound to PsGetProcessThreads iterator."`
  3. ShadowMem is a pure user-mode Win32 application; no Ring-0 kernel driver exists.
- **Impact:** Misleading presentation of technical capabilities during audits and live demonstrations.
- **Suggested Fix:** Replace fabricated Ring-0 claims with genuine telemetry: e.g. `"Win32 VirtualQueryEx memory auditing initialized in user-mode."`

#### NEW-08 [LOW] Missing `test` Script in `frontend/package.json`
- **File & Line:** `frontend/package.json:5-10`
- **Reproduction Steps:**
  1. Run `npm.cmd test` inside `frontend/`.
  2. Output: `npm error Missing script: "test"`.
- **Impact:** Automated CI/CD pipelines cannot run frontend unit or integration tests.
- **Suggested Fix:** Add a test runner (Vitest or Jest) to `devDependencies` and configure `"test": "vitest run"` in `package.json`.

---

## 6. Configuration & Logging Review

### 6.1 Status of the Settings Class (`BaseModel` vs `BaseSettings`)

- **Audit Findings:**  
  In earlier versions of the codebase, `core/config.py` inherited from standard `pydantic.BaseModel` rather than `pydantic_settings.BaseSettings`, preventing automatic parsing of `.env` files and `SHADOWMEM_*` environment variables.
- **Current Status:**  
  `core/config.py` lines 22 & 83 correctly inherit from `BaseSettings`:
  ```python
  from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

  class Settings(BaseSettings):
      model_config = SettingsConfigDict(
          env_prefix='SHADOWMEM_',
          env_file='.env',
          extra='ignore',
      )
  ```
  Verified via `tests/test_config_settings.py` (all tests passed).

### 6.2 Audit of Remaining Hardcoded Values

| File | Line(s) | Hardcoded Value | Issue / Recommended Migration to `core/config.py` |
| :--- | :--- | :--- | :--- |
| `frontend/next.config.mjs` | 18, 22 | `http://127.0.0.1:8000` | Dev-proxy targets are hardcoded to port 8000; should read `process.env.SHADOWMEM_BACKEND_URL`. |
| `frontend/src/lib/api.ts` | 42 | `http://127.0.0.1:8000` | SSR fallback URL is hardcoded; should read `process.env.NEXT_PUBLIC_BACKEND_URL`. |
| `frontend/src/context/ConnectionContext.tsx` | 118 | `3000` ms | Probe polling interval is hardcoded; should be configurable. |
| `services/supply_chain.py` | 169 | `100` modules | Directory module scan batch limit is hardcoded; should be `settings.supply_chain_batch_limit`. |
| `services/supply_chain.py` | 71–77 | `["\\temp\\", "\\downloads\\", ...]` | Suspicious path patterns are hardcoded; should be in `core/config.py`. |
| `trigger_test_event.py` | 10 | `http://localhost:8000/simulate/alert` | Hardcoded localhost URL; does not consume `settings.port`. |
| `test_master_suite.py` | 24–25 | `http://127.0.0.1:8000` | Hardcoded test target; should dynamically read `settings.port`. |

---

## 7. Security Review

### 7.1 Unauthenticated Containment Endpoints
- **Endpoints:** `POST /api/v1/isolate/{pid}`, `POST /api/v1/resume/{pid}`
- **Vulnerability:** Unauthenticated remote/local process control.
- **Analysis:** While `services/containment.py` lines 112–139 implement self-protection against suspending ShadowMem itself or protected Windows services (`csrss.exe`, `lsass.exe`, `services.exe`), any other user-mode process can be suspended by any client capable of issuing HTTP requests to the backend.
- **Remediation:** Introduce Bearer token authentication or API keys via FastAPI dependencies:
  ```python
  from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
  security = HTTPBearer()
  ```

### 7.2 Cross-Origin Resource Sharing (CORS) Misconfiguration
- **Vulnerability:** Permissive wildcard combined with credentials.
- **Analysis:** `app.py:47-51` specifies `allow_origins=settings.cors_origins` (default `["*"]`) while `allow_credentials=True`. This is both rejected by modern browsers and exposes the local API to cross-site request forgery from any web origin visited by the user.
- **Remediation:** Enforce concrete origins (`["http://localhost:3000", "http://127.0.0.1:3000"]`) when credentials are required.

### 7.3 Insecure Pickle Model Loading
- **File:** `services/forensics.py:70`, `detecter.py:27`
- **Vulnerability:** Arbitrary code execution via untrusted deserialization.
- **Analysis:** `pickle.load()` reconstructs arbitrary objects by design. If a malicious actor gains write access to `shadowmem_model.pkl`, arbitrary operating system commands will execute when the model is initialized.
- **Remediation:** Verify a cryptographic HMAC or SHA-256 signature prior to loading, or transition the pipeline to an open, structured format like ONNX.

### 7.4 Input Validation and Path Traversal
- **File:** `routers/supply_chain.py:59-75`, `services/supply_chain.py:160-172`
- **Vulnerability:** Unrestricted filesystem path traversal.
- **Analysis:** The `target_path` field in `SupplyChainScanRequest` is passed directly to `Path(dir_path)` without verifying that the target is located within authorized analysis boundaries.
- **Remediation:** Sanitize user input using `os.path.abspath` and verify that the target path resides within an allowlisted directory tree.

---

## 8. WebSocket Review

### 8.1 Active Connection Count
- **Frontend Audit:**  
  `frontend/src/context/ConnectionContext.tsx` line 121 is the **sole owner** of the active WebSocket connection. It instantiates `connectAlertsWebSocket()` once on mount and manages alert fan-out via an internal subscriber set (`alertSubscribersRef`).
- **Connection Count:**  
  Under standard operation, the frontend maintains **exactly 1** persistent WebSocket connection to `/api/v1/ws/alerts`.

### 8.2 Memory Map Frame Handling
- **Backend Behavior:**  
  On WebSocket connection establishment (`services/alerts.py:42`) and whenever process changes are detected (`services/alerts.py:102`), the backend generates and broadcasts a `memory_map` frame containing detailed block allocations (`base_address`, `size`, `protection`, `status`).
- **Frontend Behavior:**  
  In `frontend/src/lib/api.ts:245`:
  ```typescript
  if (payload.type && payload.type !== "alert") return;
  ```
- **Conclusion:**  
  **`memory_map` frames are actively and unconditionally discarded.** The radar visualizer on `live-map/page.tsx` does not consume WebSocket memory map frames; it relies entirely on full HTTP GET scans (`fetchScan()`).

---

## 9. Frontend State Audit

### 9.1 Global vs. Local State Management

The frontend state architecture is significantly fragmented:
- **Global State:**
  - `ConnectionContext`: Manages online/offline state, reconnection timing, and WebSocket alert dispatch.
  - `DensityContext`: Manages UI padding toggle (`compact` vs `default`).
  - `NotificationsContext`: Manages toast and alert badge collections.
- **Fragmented Local State:**
  - `processes`: Declared locally in 5 distinct pages (`page.tsx`, `process-table/page.tsx`, `live-map/page.tsx`, `analytics/page.tsx`, `alerts/page.tsx`).
  - `isolatedPids`: Declared locally in 3 distinct pages (`page.tsx`, `process-table/page.tsx`, `live-map/page.tsx`).
  - `kernelLogs`: Declared locally in `page.tsx` and `kernel-log/page.tsx`.

*Consequence:* Navigating between tabs destroys forensic findings, forcing redundant 20-second scans.

### 9.2 Fake, Simulated, and Ambient Ticker Telemetry

1. **Hardcoded Ring-0 Kernel Telemetry:**  
   `kernel-log/page.tsx:26-61` and `page.tsx:40-61` seed five fake logs on initialization:
   - *"VAD memory auditing filter driver initialized in Ring-0."*
   - *"NtQueryVirtualMemory handles bound to PsGetProcessThreads iterator."*
   - *"7-Feature forensic pipeline loaded: random forest classifier active."*
   - *"Validating memory page protection masks against system DEP policies."*
   - *"Memory Commit threshold verified: nominal user-mode headroom."*
2. **Pseudo-Random ID Generation:**  
   `api.ts:248`, `page.tsx:84`, and `kernel-log/page.tsx:82` use `Math.random().toString(36).substr(2, 4)` for log and alert IDs rather than cryptographic UUIDs.
3. **Orphaned Mock Dataset:**  
   `frontend/src/data/mockForensics.ts` (296 lines) exports `mockSummary`, `mockProcesses`, `mockScanHistory`, `mockAlerts`, and `mockKernelLogs`. None of these exports are imported by any active page or component; the file is dead code.

---

## 10. Supply Chain Scanner & Sandbox Evaluation

### 10.1 Real vs. Scaffolding Analysis

#### A. Supply Chain Scanner (`services/supply_chain.py`) — **REAL IMPLEMENTATION**
- **Architecture:** Uses `psutil.Process(pid).memory_maps()` to enumerate live loaded dynamic libraries (`.dll`, `.exe`, `.sys`).
- **Binary Inspection:** Invokes `pefile.PE()` to parse the PE Optional Header Data Directory (`IMAGE_DIRECTORY_ENTRY_SECURITY`) to identify embedded Authenticode digital certificates.
- **Hashing:** Computes real cryptographic SHA-256 digests of on-disk binaries via `hashlib.sha256()`.

#### B. Docker WSL2 Sandbox (`services/sandbox.py`) — **ORCHESTRATION SCAFFOLDING**
- **Real Probing:** Executes real CLI probes (`shutil.which("wsl")`, `docker info`, `subprocess.run(["wsl", "-d", distro, "docker", "info"])`).
- **Job Management:** Tracks jobs in memory via UUID and validates schemas using Pydantic.
- **Docker Detonation Reality:** **NO DOCKER RUN SUPPORT EXISTS.** Lines 135–151 contain only a placeholder comment (`# docker run --rm -m 512m --net=none shadowmem-sandbox:latest <sample>`) and immediately return a mock completed dictionary. No container is ever created, started, or inspected.

---

### 10.2 Live Execution of Supply Chain Scanner on Real Process

The supply chain scanner was executed directly on the live Python process (`os.getpid()`).

- **Command:**
  ```powershell
  .\.venv\Scripts\python.exe -c "import os; from services.supply_chain import scan_process_modules; res = scan_process_modules(os.getpid()); print(f'Target: {res.target}, Scanned: {res.total_modules_scanned}, Unsigned: {res.unsigned_count}, Suspicious: {res.suspicious_count}, Posture: {res.posture}')"
  ```
- **Real Output:**
  ```
  Target: python.exe (PID 28384), Scanned: 42, Unsigned: 2, Suspicious: 0, Posture: Suspicious
  ```
- **Module Inspection Sample Output:**
  ```json
  {
    "module_name": "ntdll.dll",
    "file_path": "C:\\Windows\\System32\\ntdll.dll",
    "is_signed": true,
    "signer_identity": "Authenticode Embedded Certificate",
    "sha256": "651ac9041af8e6b5ebd331d53163244c0a27d36d1433f0f15cac1f28c5f2e82c",
    "is_suspicious_location": false,
    "is_known_vulnerable": false,
    "anomaly_description": null
  }
  ```

---

## 11. Test Suite Audit

### 11.1 Pytest Execution Status: UNVERIFIED (Not Installed)

- **Execution Command:** `pytest --version` / `.\.venv\Scripts\python.exe -m pytest`
- **Real Output:**
  ```
  C:\Users\Himesh\Desktop\ShadowMem\.venv\Scripts\python.exe: No module named pytest
  ```
- **Status:** **UNVERIFIED via pytest.** `pytest` is neither installed in `.venv` nor declared in `requirements.txt`.

---

### 11.2 Direct Execution of Automated Test Suites

All test suites were executed directly using `python.exe`:

| Test Suite | Execution Command | Result | Details / Output Proof |
| :--- | :--- | :--- | :--- |
| **API & Schemas** | `python tests\test_api_v1_schemas.py` | **PASS (10/10)** | `ALL STEP 2 API & SCHEMA TESTS PASSED SUCCESSFULLY!` |
| **Config & Logging**| `python tests\test_config_settings.py` | **PASS (10/10)** | `ALL STEP 3 CONFIG & LOGGING TESTS PASSED SUCCESSFULLY!` |
| **Layered Arch** | `python tests\test_layered_architecture.py` | **PASS (10/10)** | `ALL STEP 4 LAYERED ARCHITECTURE TESTS PASSED SUCCESSFULLY!` |
| **Integrations** | `python tests\test_step5_integrations.py` | **PASS (10/10)** | `ALL STEP 5 INTEGRATION TESTS PASSED SUCCESSFULLY!` |
| **Sandbox Attacks**| `python test_sandbox.py` | **PASS (6/6 suites, 30 checks)** | `*** ALL TESTS PASSED - Sandbox is working correctly ***` |
| **Smoke Fixes** | `python test_fixes.py` | **PASS (4/4)** | Verified live scan, isolate 404, resume 404, dashboard HTML |
| **Master Suite** | `python test_master_suite.py` | **PASS (25/25)** | Full 6-phase validation covering injector, containment, WS alerts |
| **Frontend Lint** | `npm.cmd run lint` (in `frontend/`) | **PASS** | `✔ No ESLint warnings or errors` |
| **Frontend Tests**| `npm.cmd test` (in `frontend/`) | **FAIL (Missing)** | `npm error Missing script: "test"` |

### 11.3 Coverage Gaps
1. **Zero Frontend Unit Tests:** No unit or component test harness exists for React components.
2. **Missing Test Runner Package:** `pytest` and `pytest-cov` are missing from dependencies.
3. **No Dynamic Sandbox Execution Testing:** Because Docker execution is scaffolding, there are no tests executing real containers.

---

## 12. Demo-Readiness Checklist

### Top 5 Most Demo-able Features

| # | Feature | End-to-End Functional Today? | Exact Step-by-Step Demo Instructions |
| :--- | :--- | :--- | :--- |
| **1** | **Live Volatile Memory Forensic Audit** | **YES** | 1. Start server: `launch_shadowmem.bat`<br/>2. Open dashboard at `http://127.0.0.1:8000/`<br/>3. Click the blue **"Run Memory Audit"** button.<br/>4. Observe real Win32 `VirtualQueryEx` scan progress.<br/>5. Review the resulting summary: ~130 processes, JIT engine classification, and 0 false positives. |
| **2** | **Synthetic In-Memory Malware Injection & Detection** | **YES** | 1. Open a new terminal in the repo directory.<br/>2. Run `.\.venv\Scripts\python.exe test_injector.py` (allocates unbacked RWX pages and thread).<br/>3. On the dashboard, click **"Run Memory Audit"**.<br/>4. The injector process appears highlighted in red with a **>99% Threat Score** and status **"Malicious (Injected)"**.<br/>5. Click the injector card to view the Forensic Dossier and MITRE classification **T1620 (Shellcode / C2 Beacon)**. |
| **3** | **Active Threat Containment & Thread Suspension** | **YES** | 1. With the detected injector process open in the Forensic Dossier Modal, click **"Isolate Target Process"**.<br/>2. The backend calls `OpenThread` and `SuspendThread`, freezing all execution threads in the target.<br/>3. The UI badge updates to **"ISOLATED"** and a green confirmation toast appears.<br/>4. Click **"Resume Process (Un-isolate)"** to unfreeze the process via `ResumeThread`. |
| **4** | **Real-Time WebSocket Detection Alert Broadcasting** | **YES** | 1. Navigate to the Alerts tab (`http://127.0.0.1:8000/alerts`).<br/>2. Click **"Trigger Simulated Threat Attack"** (or execute `python trigger_test_event.py` from CLI).<br/>3. The backend dispatches a simulated Cobalt Strike reflective injection alert over the WebSocket stream.<br/>4. The Alerts page immediately updates with a critical red incident card without page refresh. |
| **5** | **Automated Forensic Engineering PDF Report Generation** | **YES** | 1. Open a terminal and run `.\.venv\Scripts\python.exe make_pdf.py`.<br/>2. ReportLab compiles `ShadowMem_Project_Report.pdf` in seconds.<br/>3. Run `python make_summary_pdf.py` to generate `ShadowMem_Summary.pdf`.<br/>4. Open the generated PDFs to present formatted executive summaries, diagrams, and MITRE ATT&CK matrices. |

---

## 13. Prioritized Fix List

Issues are ranked by ROI: $(\text{Demo Impact} / \text{Effort in Minutes})$.

### 13.1 Backend Engineering Tasks

| Priority | Task & Issue Reference | Impact | Effort (Min) | ROI Ratio | Implementation Summary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **B-1** | Fix CORS Wildcard + Credentials Misconfiguration (NEW-02) | High | 5 min | 16.0 | In `core/config.py:104`, set explicit allowed origins list; remove wildcard when credentials enabled. |
| **B-2** | Add `pytest` and `pytest-cov` to `requirements.txt` | Medium | 5 min | 10.0 | Append `pytest==8.3.4` and `pytest-cov==6.0.0` to manifest to enable standard CI test execution. |
| **B-3** | Restrict Path Traversal in `/api/v1/supply-chain/scan/path` (NEW-05) | Medium | 15 min | 4.0 | Validate `target_path` using `os.path.realpath` against approved directories before module inspection. |
| **B-4** | Enforce HMAC / SHA-256 Verification on `shadowmem_model.pkl` (NEW-06) | High | 15 min | 5.3 | Compute model SHA-256 before `pickle.load()` and compare against a known hash constant. |
| **B-5** | Secure Containment Endpoints with API Key Auth (NEW-03) | High | 25 min | 3.2 | Add FastAPI `Security(APIKeyHeader)` dependency on `/isolate` and `/resume` routes. |
| **B-6** | Replace Docker Scaffolding with Live Detonation Worker | High | 180 min | 0.5 | Implement real `docker run` orchestration in `services/sandbox.py` using Docker SDK. |

### 13.2 Frontend Engineering Tasks

| Priority | Task & Issue Reference | Impact | Effort (Min) | ROI Ratio | Implementation Summary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **F-1** | Implement Global `ForensicsContext` Store (NEW-04) | Critical | 35 min | 2.8 | Create `ForensicsContext.tsx` providing `processes`, `summary`, and `runScan` to eliminate blank pages on tab navigation. |
| **F-2** | Ingest and Render WebSocket `memory_map` Frames (NEW-01) | High | 25 min | 3.2 | In `api.ts:245`, handle `type === "memory_map"` and dispatch blocks to the live radar map component. |
| **F-3** | Cleanse Fake Ring-0 Seed Logs from Telemetry Pages (NEW-07) | Medium | 10 min | 5.0 | Remove fictitious Ring-0 driver strings from initial state in `kernel-log/page.tsx` and `page.tsx`. |
| **F-4** | Expose Supply Chain Scanner UI Tab | High | 45 min | 1.8 | Add a dedicated `/supply-chain` route in Next.js displaying loaded module Authenticode signatures and SHA-256 hashes. |
| **F-5** | Add Frontend Test Suite with Vitest & React Testing Library (NEW-08) | Medium | 30 min | 1.7 | Configure `vitest` in `package.json` and create smoke tests for `Header`, `Sidebar`, and `ProcessTable`. |

---
*Report certified complete and verified against live system telemetry.*
