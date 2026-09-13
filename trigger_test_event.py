#!/usr/bin/env python3
"""
Trigger a simulated in-memory attack alert in ShadowMem.
Posts to the FastAPI /simulate/alert endpoint which broadcasts to all connected WebSockets.
"""
import urllib.request
import json
import sys

URL = "http://localhost:8000/simulate/alert"
payload = {
    "scenario": "cobalt_strike_reflective_injection",
    "severity": "critical"
}

try:
    req = urllib.request.Request(
        URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        res_data = json.loads(resp.read().decode("utf-8"))
        print(f"[+] Simulation Event Dispatched Successfully! Status: {res_data.get('status')}")
        print(f"[+] Alert Event ID: {res_data.get('alert_id')}")
except Exception as e:
    print(f"[-] Error dispatching simulation event: {e}")
    print("    Ensure server is running: python -m uvicorn server:app --port 8000")
    sys.exit(1)
