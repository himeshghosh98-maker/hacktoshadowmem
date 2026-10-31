"""
services/alerts.py
==================
WebSocket alert broadcasting, live memory-map generation, background ticker,
and attack scenario simulation.
"""

import asyncio
import datetime as _dt
import random
import uuid
from typing import List, Dict, Tuple, Optional, Any
from fastapi import WebSocket

from core.config import settings
from core.logging import logger
from services.forensics import (
    get_cached_processes,
    set_cached_processes,
    perform_scan_and_diff,
)


class ConnectionManager:
    """Tracks active WebSocket dashboard connections and broadcasts alert frames."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            "WebSocket client connected. Total active connections: %d",
            len(self.active_connections),
        )

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(
                "WebSocket client disconnected. Total active connections: %d",
                len(self.active_connections),
            )

    async def broadcast(self, message: dict) -> None:
        disconnected: List[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        for dead in disconnected:
            self.disconnect(dead)


# Global WebSocket connection manager singleton
ws_manager = ConnectionManager()

# Background ticker task handle
_scan_ticker_task: Optional[asyncio.Task] = None


def threat_alert_frame(proc: Dict[str, Any], previous_status: Optional[str]) -> dict:
    """Build a WebSocket alert frame from an evaluated process record."""
    classification = proc.get("classification") or {}
    technique = None
    if classification.get("mitre_id") and classification.get("display_name"):
        technique = f"{classification['mitre_id']} — {classification['display_name']}"
    elif classification.get("display_name"):
        technique = classification["display_name"]

    status = str(proc.get("status") or "")
    malicious = status == "Malicious (Injected)"
    threat_score = float(proc.get("threat_score") or 0.0)
    was = previous_status or "unscanned"

    return {
        "type": "alert",
        "event_id": str(uuid.uuid4()),
        "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "severity": "critical" if malicious else "warn",
        "process": {
            "pid": proc.get("pid"),
            "name": proc.get("name"),
            "image_path": proc.get("exe") or "",
        },
        "detection": {
            "is_malicious": malicious,
            "confidence": round(threat_score / 100.0, 2),
            "classifier": "ShadowMem-v1",
            "technique": technique,
            "threat_score": threat_score,
            "status": status,
        },
        "message": (
            f"Process {proc.get('name')} (PID {proc.get('pid')}) classified as "
            f"{status} (score {threat_score:.1f}/100, was {was})."
        ),
    }


def build_memory_map(evaluated: Optional[List[Dict[str, Any]]] = None) -> dict:
    """
    Build a memory_map frame from real scanned process memory regions.
    Uses cached processes if evaluated is None.
    """
    if evaluated is None:
        evaluated = get_cached_processes()

    focus = next((p for p in evaluated if p.get("unbacked_regions")), None)
    if focus is None and evaluated:
        focus = evaluated[0]

    blocks: List[Dict[str, Any]] = []
    if focus is not None:
        focus_status = str(focus.get("status") or "")
        malicious = focus_status == "Malicious (Injected)"
        in_threat_set = focus_status in settings.threat_statuses
        unbacked = focus.get("unbacked_regions") or []
        for i, region in enumerate(unbacked[: settings.max_region_details]):
            protection = str(region.get("protection") or "")
            if not in_threat_set:
                block_status = "clean"
            elif malicious and protection == "PAGE_EXECUTE_READWRITE":
                block_status = "infected"
            else:
                block_status = "suspicious"
            blocks.append({
                "index": i,
                "base_address": f"0x{int(region.get('base_address') or 0):016X}",
                "size": int(region.get("size") or 0),
                "protection": protection,
                "state": "MEM_COMMIT",
                "type": "MEM_PRIVATE",
                "status": block_status,
            })

    return {
        "type": "memory_map",
        "event_id": str(uuid.uuid4()),
        "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "process": (
            {
                "pid": focus.get("pid"),
                "name": focus.get("name"),
                "status": focus.get("status"),
            }
            if focus is not None
            else None
        ),
        "blocks": blocks,
    }


async def broadcast_scan_updates(
    changes: List[Tuple[Dict[str, Any], Optional[str]]],
) -> None:
    """Broadcast one threat alert per newly detected process, then a fresh memory map."""
    for proc, prev_status in changes:
        logger.info(
            "WS alert: pid=%s %s score=%s (was %s)",
            proc.get("pid"),
            proc.get("name"),
            proc.get("threat_score"),
            prev_status or "first scan",
        )
        await ws_manager.broadcast(threat_alert_frame(proc, prev_status))
    await ws_manager.broadcast(build_memory_map())


async def scan_ticker_loop() -> None:
    """Background ticker loop: periodic memory scans diffed against previous state."""
    logger.info("WS alert ticker started (real scans every %.0fs)", settings.scan_interval_seconds)
    while True:
        try:
            if ws_manager.active_connections:
                _evaluated, changes = await asyncio.to_thread(perform_scan_and_diff)
                await broadcast_scan_updates(changes)
        except Exception as exc:  # noqa: BLE001
            logger.error("WS alert ticker scan failed: %s", exc)
        await asyncio.sleep(settings.scan_interval_seconds)


def ensure_scan_ticker() -> None:
    """Start the background scan ticker if not already running."""
    global _scan_ticker_task
    if _scan_ticker_task is None or _scan_ticker_task.done():
        _scan_ticker_task = asyncio.create_task(scan_ticker_loop())


# ---- Simulated Attack Scenarios --------------------------------------------
SIMULATE_SCENARIOS: Dict[str, Tuple[str, str]] = {
    "cobalt_strike_reflective_injection": (
        "T1620",
        "Reflective Code Loading (Cobalt Strike Beacon pattern)",
    ),
    "process_hollowing": ("T1055.012", "Process Hollowing"),
    "dll_injection": ("T1055.001", "Dynamic-link Library Injection"),
}
SIMULATE_SEVERITIES = ("critical", "warn", "info")

SIMULATE_TARGETS = (
    ("rundll32.exe", 7488, r"C:\Windows\System32\rundll32.exe"),
    ("powershell.exe", 6172, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ("spoolsv.exe", 3216, r"C:\Windows\System32\spoolsv.exe"),
)


async def simulate_attack_alert(scenario: str, severity: str) -> dict:
    """Broadcast a test alert and memory map frame for simulation harnesses."""
    scenario = scenario.strip()
    if scenario not in SIMULATE_SCENARIOS:
        raise ValueError(
            f"Unknown scenario '{scenario}'. Valid scenarios: {', '.join(SIMULATE_SCENARIOS)}."
        )

    severity = severity.strip().lower()
    if severity not in SIMULATE_SEVERITIES:
        raise ValueError(
            f"Unknown severity '{severity}'. Valid severities: {', '.join(SIMULATE_SEVERITIES)}."
        )

    technique_id, technique_name = SIMULATE_SCENARIOS[scenario]
    name, pid, path = random.choice(SIMULATE_TARGETS)

    # Build simulated process record with rich forensic detail
    simulated_proc: Dict[str, Any] = {
        "pid": pid,
        "name": name,
        "exe": path,
        "rwx_count": 3,
        "unbacked_exec_count": 2,
        "total_rwx_bytes": 131072,
        "allocated_kb": 128.0,
        "num_threads": 8,
        "thread_unbacked_start": 1,
        "vad_protection_anomaly": 2,
        "threat_score": 96.5,
        "status": "Malicious (Injected)",
        "jit_engine": False,
        "model_used": True,
        "classification": {
            "mitre_id": technique_id,
            "display_name": technique_name,
            "short_description": "Adversary injects malicious executable payload into target address space without touching disk.",
            "typical_indicators": "Unbacked executable memory buffer (PAGE_EXECUTE_READWRITE) with thread entry point mismatch.",
            "recommended_response": "Suspend active process threads via NtSuspendProcess and isolate network connectivity.",
        },
        "unbacked_regions": [
            {
                "base_address": 0x7FFA2B400000,
                "size": 65536,
                "protection": "PAGE_EXECUTE_READWRITE",
                "allocation_protect": "PAGE_READWRITE",
            },
            {
                "base_address": 0x7FFA2B420000,
                "size": 65536,
                "protection": "PAGE_EXECUTE_READ",
                "allocation_protect": "PAGE_READWRITE",
            },
        ],
        "attribution": {
            "thread_unbacked_start": 45.0,
            "rwx_allocations": 35.0,
            "vad_protection_anomaly": 20.0,
        },
        "attribution_reasons": [
            "1 active thread initialized directly inside unbacked executable memory (0x7FFA2B400000)",
            "3 PAGE_EXECUTE_READWRITE allocations detected in private memory (128 KB)",
            "2 memory permission flip anomalies (PAGE_READWRITE -> PAGE_EXECUTE_READWRITE)",
        ],
    }

    # Inject into cached processes list so dashboard reflects it immediately
    current_cache = list(get_cached_processes())
    # Remove existing entry if PID already in cache
    current_cache = [p for p in current_cache if p.get("pid") != pid]
    current_cache.insert(0, simulated_proc)
    set_cached_processes(current_cache)

    alert = {
        "type": "alert",
        "event_id": str(uuid.uuid4()),
        "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "severity": severity,
        "process": {"pid": pid, "name": name, "image_path": path},
        "detection": {
            "is_malicious": True,
            "confidence": 0.96,
            "classifier": "ShadowMem-v1",
            "technique": f"{technique_id} — {technique_name}",
            "threat_score": 96.5,
            "status": "Malicious (Injected)",
            "scenario": scenario,
        },
        "message": f"Simulated {scenario} detection: {name} (PID {pid}) — {technique_name}",
    }

    await ws_manager.broadcast(alert)
    await ws_manager.broadcast(build_memory_map(current_cache))

    return {
        "status": "broadcast",
        "alert_id": alert["event_id"],
        "scenario": scenario,
        "severity": severity,
        "process": simulated_proc,
    }
