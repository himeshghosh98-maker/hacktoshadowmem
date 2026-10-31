"""
routers/alerts.py
=================
API routes for WebSocket alert feeds, real-time memory-map streaming,
and simulated attack detection event broadcasting.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException

from schemas.alerts import (
    SimulateAlertRequest,
    SimulateAlertResponse,
)
from services.alerts import (
    ws_manager,
    build_memory_map,
    ensure_scan_ticker,
    simulate_attack_alert,
)

router = APIRouter(tags=["Alerts & Simulation (v1)"])
compat_router = APIRouter(tags=["Alerts & Simulation (Compat)"])


@router.websocket("/ws/alerts")
@compat_router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    WebSocket endpoint for streaming detection alerts and memory maps to dashboards.
    Sends initial welcome frame and memory map, then stays open for live broadcasts.
    """
    await ws_manager.connect(websocket)
    try:
        # Welcome frame
        await websocket.send_json({
            "type": "alert",
            "event_id": "welcome-0000",
            "severity": "info",
            "message": "WebSocket link established — awaiting scan events.",
        })
        # Initial memory map frame
        await websocket.send_json(build_memory_map())
        # Start shared background scan ticker
        ensure_scan_ticker()
        # Keep connection open and detect client disconnects
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


@router.post(
    "/simulate/alert",
    response_model=SimulateAlertResponse,
    summary="Broadcast simulated detection alert",
    description="Broadcasts a test alert and memory map frame across the WebSocket stream (/ws/alerts).",
)
@compat_router.post(
    "/simulate/alert",
    response_model=SimulateAlertResponse,
    summary="Broadcast simulated detection alert (compat)",
    description="Legacy simulation trigger endpoint for test harnesses and backward compatibility.",
)
async def simulate_alert(req: SimulateAlertRequest):
    """Broadcast a simulated attack alert + memory map."""
    try:
        result = await simulate_attack_alert(req.scenario, req.severity)
        return result
    except ValueError as verr:
        raise HTTPException(status_code=400, detail=str(verr)) from verr
