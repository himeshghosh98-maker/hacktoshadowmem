"""
test_master_suite.py -- ShadowMem Master End-to-End Test Suite
================================================================
Executes a rigorous, 6-phase validation covering all upgrades:
  Phase 1: Unit & Sandbox Simulations (test_sandbox.py)
  Phase 2: Live Server API & Health (FastAPI / Uvicorn)
  Phase 3: Live In-Memory Injection & Detection (test_injector.py + /api/scan)
  Phase 4: Active Response Containment & Rollback (/api/isolate, /api/resume, /api/audit)
  Phase 5: WebSocket Real-Time Alert Broadcast (/ws/alerts + /simulate/alert)
  Phase 6: Forensic Reporting Engine (PDF generators)
"""

import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
import psutil

VENV_PYTHON = sys.executable
BASE_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws/alerts"

passed_tests = 0
failed_tests = 0


def log_phase(title):
    print("\n" + "=" * 75)
    print(f"  {title.upper()}")
    print("=" * 75)


def check(name, condition, details=""):
    global passed_tests, failed_tests
    if condition:
        passed_tests += 1
        print(f"  [PASS] {name} {f'({details})' if details else ''}")
    else:
        failed_tests += 1
        print(f"  [FAIL] {name} {f'({details})' if details else ''}")


def http_get(path, timeout=30):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read()


def http_post(path, data=None, timeout=15):
    url = f"{BASE_URL}{path}"
    body = json.dumps(data).encode("utf-8") if data else b""
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# ---------------------------------------------------------------------------
# Phase 1: Sandbox Unit Test Suite
# ---------------------------------------------------------------------------
log_phase("Phase 1: Sandbox & Forensic Classifier Test Suite (test_sandbox.py)")
p1 = subprocess.run([VENV_PYTHON, "test_sandbox.py"], capture_output=True, text=True)
sandbox_ok = (p1.returncode == 0) and ("ALL TESTS PASSED" in p1.stdout)
check("test_sandbox.py execution", sandbox_ok, "6/6 attack suites passed")
if not sandbox_ok:
    print(p1.stdout)
    print(p1.stderr)


# ---------------------------------------------------------------------------
# Phase 2: Live Server API & UI Verification
# ---------------------------------------------------------------------------
log_phase("Phase 2: Live Server API & UI Health Verification")
code, html_bytes = http_get("/")
check("Dashboard Root HTML (GET /)", code == 200 and len(html_bytes) > 50000, f"{len(html_bytes)} bytes served")

html_text = html_bytes.decode("utf-8", "ignore")
check("Dark Theme Palette (#060A13)", "#060A13" in html_text, "Surface hierarchy active")
check("Single let isolatedPids Declaration", html_text.count("let isolatedPids") == 1, "Duplicate bug resolved")
check("Interactive Scan Button Handler", "scanBtn.addEventListener" in html_text, "Event listener bound")


# ---------------------------------------------------------------------------
# Phase 3: Live In-Memory Injection & Real-Time Detection
# ---------------------------------------------------------------------------
log_phase("Phase 3: Live In-Memory Injection & Detection")

injector_proc = subprocess.Popen(
    [VENV_PYTHON, "-u", "test_injector.py"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
time.sleep(2.5)  # Allow injector to spawn child process and allocate unbacked RWX pages

# In Windows virtualenvs, the launcher process spawns the worker child
parent_proc = psutil.Process(injector_proc.pid)
children = parent_proc.children()
actual_pid = children[0].pid if children else injector_proc.pid
print(f"[*] Test injector running with PID {actual_pid} (parent: {injector_proc.pid})...")

try:
    print("[*] Running live system memory scan via GET /api/scan...")
    t0 = time.time()
    code, scan_bytes = http_get("/api/scan", timeout=60)
    scan_duration = time.time() - t0
    scan_data = json.loads(scan_bytes.decode("utf-8"))
    
    check("API Scan Status (GET /api/scan)", code == 200, f"Scanned {scan_data['summary']['total_scanned']} processes in {scan_duration:.1f}s")
    
    # Locate injector process in scan results
    target = None
    for p in scan_data.get("processes", []):
        if p["pid"] == actual_pid:
            target = p
            break
            
    check("Injector Process Discovered in Live RAM", target is not None, f"PID {actual_pid}")
    if target:
        score = target["threat_score"]
        status = target["status"]
        rwx = target["rwx_count"]
        unbacked_thread = target["thread_unbacked_start"]
        vad_flip = target["vad_protection_anomaly"]
        technique = (target.get("classification") or {}).get("display_name", "None")
        
        check("RWX Allocations Detected", rwx >= 1, f"Count: {rwx}")
        check("Unbacked Thread Start Detected", unbacked_thread >= 1, f"Count: {unbacked_thread}")
        check("VAD Protection Anomaly Detected", vad_flip >= 1, f"Count: {vad_flip}")
        check("Threat Score >= 70%", score >= 70.0, f"Calculated: {score:.2f}%")
        check("Verdict == Malicious (Injected)", status == "Malicious (Injected)", f"Status: {status}")
        check("MITRE Technique Classification", technique != "None", f"Classified as: {technique}")

    # -----------------------------------------------------------------------
    # Phase 4: Active Remediation & Rollback Containment
    # -----------------------------------------------------------------------
    log_phase("Phase 4: Active Remediation & Rollback Containment")
    
    # 4A. Suspend live injector
    code, iso_bytes = http_post(f"/api/isolate/{actual_pid}")
    iso_res = json.loads(iso_bytes.decode("utf-8"))
    check("Process Containment (POST /api/isolate)", code == 200 and iso_res.get("success") is True, 
          f"Suspended {iso_res.get('suspended_count', 0)} thread(s)")
    
    # 4B. Verify audit logging
    code, audit_bytes = http_get("/api/audit")
    audit_data = json.loads(audit_bytes.decode("utf-8"))
    actions = audit_data.get("actions", [])
    last_audit = actions[-1] if actions else {}
    check("Audit Trail Record Created", last_audit.get("pid") == actual_pid and last_audit.get("action") == "isolate",
          f"Action: {last_audit.get('action')}, Result: {'success' if last_audit.get('success') else 'failure'}")
    
    # 4C. Resume live injector
    code, res_bytes = http_post(f"/api/resume/{actual_pid}")
    res_res = json.loads(res_bytes.decode("utf-8"))
    check("Process Rollback (POST /api/resume)", code == 200 and res_res.get("success") is True,
          f"Resumed {res_res.get('resumed_count', 0)} thread(s)")
    
    # 4D. Find server PID and test self-protection guard
    server_pid = None
    for conn in psutil.net_connections(kind="tcp"):
        if conn.laddr.port == 8000 and conn.status == psutil.CONN_LISTEN:
            server_pid = conn.pid
            break
    if server_pid:
        code, self_bytes = http_post(f"/api/isolate/{server_pid}")
        check("Self-Protection Guard", code == 403, f"Server PID {server_pid} protected (HTTP 403)")
    else:
        # Fallback to testing System process (PID 4)
        code, sys_bytes = http_post("/api/isolate/4")
        check("System Process Protection Guard", code == 403, "System PID 4 protected (HTTP 403)")
    
    # 4E. Nonexistent PID handling
    code, bad_bytes = http_post("/api/isolate/999999")
    check("Nonexistent PID Graceful 404", code == 404, "Handles dead PID cleanly")

finally:
    # Clean up the injector process tree
    print("[*] Terminating test injector process tree...")
    try:
        if children:
            for c in children:
                c.terminate()
        injector_proc.terminate()
        injector_proc.wait(timeout=3.0)
    except Exception:
        pass
    print("[+] Test injector stopped cleanly.")


# ---------------------------------------------------------------------------
# Phase 5: WebSocket Real-Time Alert Broadcast
# ---------------------------------------------------------------------------
log_phase("Phase 5: WebSocket Real-Time Alert Streaming")

async def test_websocket_broadcast():
    import websockets
    received_messages = []
    
    async with websockets.connect(WS_URL) as ws:
        # Welcome message
        welcome = await asyncio.wait_for(ws.recv(), timeout=5.0)
        received_messages.append(json.loads(welcome))
        
        # Trigger an alert broadcast via HTTP POST
        code, sim_bytes = http_post("/simulate/alert")
        sim_data = json.loads(sim_bytes.decode("utf-8"))
        
        # Receive the broadcasted alert
        alert = await asyncio.wait_for(ws.recv(), timeout=5.0)
        received_messages.append(json.loads(alert))
        
        return sim_data, received_messages

try:
    sim_data, ws_msgs = asyncio.run(test_websocket_broadcast())
    welcome_msg = ws_msgs[0]
    broadcast_msg = ws_msgs[1]
    check("WebSocket Handshake & Welcome", welcome_msg.get("type") == "alert", "Link established")
    check("WebSocket Alert Broadcast", broadcast_msg.get("event_id") == sim_data.get("alert_id"), 
          f"Broadcast event {broadcast_msg.get('event_id')[:8]}... received")
    check("Alert Payload Technique Metadata", "Reflective Code Loading" in str(broadcast_msg), "MITRE info present")
except Exception as e:
    check("WebSocket Broadcast", False, str(e))


# ---------------------------------------------------------------------------
# Phase 6: Forensic PDF Report Generators
# ---------------------------------------------------------------------------
log_phase("Phase 6: Forensic PDF & Presentation Guide Engines")

p_pdf = subprocess.run([VENV_PYTHON, "make_pdf.py"], capture_output=True, text=True)
check("make_pdf.py (ShadowMem_Project_Report.pdf)", p_pdf.returncode == 0, "Project report compiled")

p_sum = subprocess.run([VENV_PYTHON, "make_summary_pdf.py"], capture_output=True, text=True)
check("make_summary_pdf.py (ShadowMem_Summary.pdf)", p_sum.returncode == 0, "Executive summary compiled")

p_err = subprocess.run([VENV_PYTHON, "make_error_report_pdf.py"], capture_output=True, text=True)
check("make_error_report_pdf.py (ShadowMem_Errors_To_Fix.pdf)", p_err.returncode == 0, "Rectification report compiled")

p_gui = subprocess.run([VENV_PYTHON, "make_guide.py"], capture_output=True, text=True)
check("make_guide.py (presentation_guide.html)", p_gui.returncode == 0, "Presentation guide compiled")


# ---------------------------------------------------------------------------
# Final Summary
# ---------------------------------------------------------------------------
log_phase("Validation Results Summary")
total_tests = passed_tests + failed_tests
print(f"\nTOTAL VERIFICATIONS: {total_tests}")
print(f"PASSED             : {passed_tests}")
print(f"FAILED             : {failed_tests}")

if failed_tests == 0:
    print("\n" + "*" * 75)
    print("  ALL TESTS PASSED -- SHADOWMEM IS 100% OPERATIONAL AND VALIDATED!")
    print("*" * 75)
    sys.exit(0)
else:
    print("\n[!] WARNING: One or more verifications failed.")
    sys.exit(1)
