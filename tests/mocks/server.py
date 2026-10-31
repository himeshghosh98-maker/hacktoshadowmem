"""
ShadowMem SOC Dashboard — Backend (MOCK / TESTING STUB)
=========================================================

*** THIS IS NOT THE PRODUCTION SERVER ***

This is a standalone mock server for isolated frontend testing without the
real Win32 memory-scanning engine. It generates SYNTHETIC data only.

The authoritative production server is app.py, started by launch_shadowmem.bat.
app.py now includes /ws/alerts and /simulate/alert routes migrated from here,
so this file is only needed for standalone index.html testing.

FastAPI server exposing a WebSocket endpoint (`/ws/alerts`) that streams
SIMULATED process-memory telemetry and malware-detection alerts for a
hackathon dashboard demo.

Everything here is synthetic data generation for UI-testing purposes:
- No real process memory is read.
- No real VAD/PEB parsing happens.
- No injection, shellcode, or exploitation primitives are implemented.
- The "XGBoost classifier" is a stubbed confidence-score generator.

Message types sent over the socket:
  - "telemetry"   -> periodic heartbeat memory snapshot for a monitored process
  - "memory_map"  -> a simplified virtual memory layout for the visualizer
  - "alert"       -> a detection event (benign heartbeat or simulated attack)

Run (from tests/mocks/, standalone, for index.html testing only):
    pip install fastapi uvicorn --break-system-packages
    uvicorn server:app --reload --port 8082

The bind port comes from the centralized configuration (core/config.py):
SHADOWMEM_MOCK_PORT (default 8082) keeps this mock distinct from the
authoritative app.py server on SHADOWMEM_PORT (default 8000).

Test manually:
    python trigger_test_event.py
"""

import asyncio
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

# This fixture lives under tests/mocks/, so put the repository root on sys.path
# to read the same centralized configuration the real server uses.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.config import settings

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="ShadowMem SOC Dashboard API")

# Loosened for hackathon demo purposes only — tighten before any real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MITRE_TECHNIQUES = [
    ("T1055.001", "Dynamic-link Library Injection"),
    ("T1055.002", "Portable Executable Injection"),
    ("T1055.012", "Process Hollowing"),
    ("T1620", "Reflective Code Loading"),
    ("T1027.007", "Dynamic API Resolution"),
]

SAMPLE_PROCESSES = [
    ("explorer.exe", 4123, 812, r"C:\Windows\explorer.exe"),
    ("svchost.exe", 2044, 812, r"C:\Windows\System32\svchost.exe"),
    ("winword.exe", 5560, 812, r"C:\Program Files\Microsoft Office\winword.exe"),
    ("powershell.exe", 6172, 4123, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ("rundll32.exe", 7488, 2044, r"C:\Windows\System32\rundll32.exe"),
]

MEMORY_PROTECTIONS = ["PAGE_READONLY", "PAGE_READWRITE", "PAGE_EXECUTE_READ", "PAGE_EXECUTE_READWRITE"]


class ConnectionManager:
    """Tracks active WebSocket clients and fans out broadcasts to all of them."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        stale = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                stale.append(connection)
        for connection in stale:
            self.disconnect(connection)


manager = ConnectionManager()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hex_addr(n: int) -> str:
    return f"0x{n:016X}"


def make_memory_map(infected: bool = False, region_count: int = 24) -> dict:
    """Builds a simplified virtual address space layout for the visualizer."""
    blocks = []
    base = 0x00007FF600000000
    infected_index = random.randint(region_count // 2, region_count - 2) if infected else -1

    for i in range(region_count):
        size = random.choice([0x1000, 0x2000, 0x4000, 0x10000])
        is_infected_block = i == infected_index
        status = "infected" if is_infected_block else random.choices(
            ["clean", "suspicious"], weights=[0.92, 0.08]
        )[0]
        blocks.append({
            "index": i,
            "base_address": _hex_addr(base),
            "size": size,
            "protection": "PAGE_EXECUTE_READWRITE" if is_infected_block else random.choice(MEMORY_PROTECTIONS),
            "state": "MEM_COMMIT",
            "type": "MEM_PRIVATE" if is_infected_block else random.choice(["MEM_PRIVATE", "MEM_MAPPED", "MEM_IMAGE"]),
            "status": status,  # clean | suspicious | infected  (drives visualizer color)
        })
        base += size

    return {
        "type": "memory_map",
        "timestamp": _now_iso(),
        "blocks": blocks,
    }


def make_telemetry(process=None) -> dict:
    """A benign periodic heartbeat snapshot — matches the ShadowMem telemetry schema."""
    name, pid, ppid, path = process or random.choice(SAMPLE_PROCESSES)
    inference_ms = round(random.uniform(180, 850), 1)

    return {
        "type": "telemetry",
        "event_id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "host": {"hostname": "WORKSTATION-07", "ip": "10.20.4.55"},
        "process": {"pid": pid, "ppid": ppid, "name": name, "image_path": path},
        "vad_info": {
            "vad_type": "VadImageMap",
            "commit_charge": random.randint(64, 4096),
            "private_memory": False,
        },
        "peb_info": {
            "image_base_address": _hex_addr(0x00007FF700000000),
            "loaded_modules": random.randint(40, 180),
        },
        "detection": {
            "is_malicious": False,
            "confidence": round(random.uniform(0.01, 0.15), 4),
            "classifier": "XGBoost-ShadowMem-v1",
            "technique": None,
            "inference_time_ms": inference_ms,
        },
        "severity": "info",
    }


def make_alert(technique_id: str = None, technique_name: str = None, process=None,
               confidence: float = None, severity: str = "critical") -> dict:
    """A detection event — used both for randomized demo alerts and the manual trigger script."""
    name, pid, ppid, path = process or random.choice(SAMPLE_PROCESSES[1:])  # skip explorer.exe as target
    if technique_id is None:
        technique_id, technique_name = random.choice(MITRE_TECHNIQUES)
    if confidence is None:
        confidence = round(random.uniform(0.88, 0.997), 4)
    inference_ms = round(random.uniform(210, 849), 1)

    return {
        "type": "alert",
        "event_id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "host": {"hostname": "WORKSTATION-07", "ip": "10.20.4.55"},
        "process": {"pid": pid, "ppid": ppid, "name": name, "image_path": path},
        "memory_region": {
            "base_address": _hex_addr(random.randint(0x00007FF600000000, 0x00007FF6FFFFFFFF)),
            "size": random.choice([0x1000, 0x4000, 0x10000]),
            "protection": "PAGE_EXECUTE_READWRITE",
            "state": "MEM_COMMIT",
            "type": "MEM_PRIVATE",
        },
        "vad_info": {
            "vad_type": "VadNone",
            "commit_charge": random.randint(4, 64),
            "private_memory": True,
        },
        "peb_info": {
            "image_base_address": _hex_addr(0x00007FF700000000),
            "loaded_modules": random.randint(40, 180),
            "unbacked_executable_region": True,
        },
        "detection": {
            "is_malicious": True,
            "confidence": confidence,
            "classifier": "XGBoost-ShadowMem-v1",
            "technique": f"{technique_id} — {technique_name}",
            "inference_time_ms": inference_ms,
        },
        "severity": severity,
    }


class SimulateAlertRequest(BaseModel):
    scenario: str = "cobalt_strike_reflective_injection"
    severity: str = "critical"


@app.get("/")
async def root():
    return {
        "service": "ShadowMem SOC Dashboard API",
        "websocket": "/ws/alerts",
        "trigger_endpoint": "POST /simulate/alert",
    }


@app.post("/simulate/alert")
async def simulate_alert(req: SimulateAlertRequest):
    """
    Manually trigger a simulated detection event and broadcast it to every
    connected dashboard client. Called by trigger_test_event.py.

    This endpoint only assembles a JSON payload shaped like a real detection —
    it does not touch any process memory or perform any injection technique.
    """
    scenario_map = {
        "cobalt_strike_reflective_injection": ("T1620", "Reflective Code Loading (Cobalt Strike Beacon pattern)"),
        "process_hollowing": ("T1055.012", "Process Hollowing"),
        "dll_injection": ("T1055.001", "Dynamic-link Library Injection"),
    }
    technique_id, technique_name = scenario_map.get(
        req.scenario, ("T1620", "Reflective Code Loading (Cobalt Strike Beacon pattern)")
    )

    alert = make_alert(
        technique_id=technique_id,
        technique_name=technique_name,
        process=random.choice([("rundll32.exe", 7488, 2044, r"C:\Windows\System32\rundll32.exe"),
                                ("powershell.exe", 6172, 4123, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]),
        severity=req.severity,
    )
    mem_map = make_memory_map(infected=True)

    await manager.broadcast(alert)
    await manager.broadcast(mem_map)

    return {"status": "broadcast", "alert_id": alert["event_id"]}


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send an initial clean memory map so the visualizer has something to render immediately.
        await websocket.send_json(make_memory_map(infected=False))

        while True:
            await asyncio.sleep(random.uniform(1.5, 3.0))

            # ~85% of ticks are benign telemetry heartbeats, ~15% are randomized demo alerts,
            # so the dashboard has continuous background activity even without manual triggers.
            if random.random() < 0.85:
                await manager.broadcast(make_telemetry())
            else:
                await manager.broadcast(make_alert())
                await manager.broadcast(make_memory_map(infected=True))

    except WebSocketDisconnect:
        manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=settings.mock_port)