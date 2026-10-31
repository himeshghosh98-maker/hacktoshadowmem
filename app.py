"""
app.py
======
ShadowMem — Automated Volatile Memory Forensics & Fileless Malware Detection.
FastAPI Application Bootstrap & Layer Coordinator.
"""

import os
from pathlib import Path
from typing import List, Dict, Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from core.config import settings
from core.logging import logger
from routers import v1_router, compat_router

# Re-exports for forensic and router handlers
from services.forensics import (
    load_model,
    evaluate_process,
    classify_score,
    is_jit_engine,
    is_benign_managed_runtime,
    get_cached_processes,
    get_scan_lock,
)
from routers.forensics import api_scan
from routers.containment import api_isolate, api_resume, api_audit
from routers.alerts import simulate_alert, websocket_alerts


# --------------------------------------------------------------------------
# FastAPI Application Factory
# --------------------------------------------------------------------------
app = FastAPI(
    title=settings.app_title,
    description=settings.app_description,
    version=settings.app_version,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------
# Mount Versioned and Compatibility API Routers
# --------------------------------------------------------------------------
app.include_router(v1_router)
app.include_router(compat_router)


# --------------------------------------------------------------------------
# Embedded Fallback Dashboard Template Loading
# --------------------------------------------------------------------------
_FALLBACK_TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "fallback_dashboard.html"
if _FALLBACK_TEMPLATE_PATH.is_file():
    INDEX_HTML = _FALLBACK_TEMPLATE_PATH.read_text(encoding="utf-8")
else:
    INDEX_HTML = "<html><body><h1>ShadowMem</h1><p>Dashboard template not found.</p></body></html>"


# --------------------------------------------------------------------------
# Frontend Routing (Next.js Static Export with Embedded HTML Fallback)
# --------------------------------------------------------------------------
FRONTEND_OUT = str(settings.frontend_dir)

if os.path.exists(FRONTEND_OUT):
    _next_static = os.path.join(FRONTEND_OUT, "_next")
    if os.path.exists(_next_static):
        app.mount("/_next", StaticFiles(directory=_next_static), name="next_static")

    @app.get("/", response_class=HTMLResponse)
    def root() -> HTMLResponse:
        idx_path = os.path.join(FRONTEND_OUT, "index.html")
        if os.path.isfile(idx_path):
            with open(idx_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse(content=INDEX_HTML)

    @app.get("/{route_path:path}")
    def serve_frontend_routes(route_path: str):
        clean = route_path.strip("/")
        candidates = [
            os.path.join(FRONTEND_OUT, clean, "index.html"),
            os.path.join(FRONTEND_OUT, f"{clean}.html"),
            os.path.join(FRONTEND_OUT, clean),
        ]
        for c in candidates:
            if os.path.isfile(c):
                if c.endswith(".html"):
                    with open(c, "r", encoding="utf-8") as f:
                        return HTMLResponse(content=f.read())
                return FileResponse(c)
        idx_path = os.path.join(FRONTEND_OUT, "index.html")
        if os.path.isfile(idx_path):
            with open(idx_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse(content=INDEX_HTML)
else:
    @app.get("/", response_class=HTMLResponse)
    def root() -> HTMLResponse:
        return HTMLResponse(content=INDEX_HTML)


# --------------------------------------------------------------------------
# Backward-Compatibility Symbols & Bindings
# --------------------------------------------------------------------------
all_processes: List[Dict[str, Any]] = get_cached_processes()
MODEL_PATH = settings.model_path
THRESHOLD_MALICIOUS = settings.threshold_malicious
THRESHOLD_SUSPICIOUS = settings.threshold_suspicious
JIT_SCORE_CAP = settings.jit_score_cap
JIT_ENGINE_ALLOWLIST = settings.jit_engine_allowlist
MANAGED_RUNTIME_NAMES = settings.managed_runtime_names
MANAGED_RUNTIME_PATH_PREFIXES = settings.managed_runtime_path_prefixes
CRITICAL_SYSTEM_PROCESSES = settings.critical_system_processes
SCAN_INTERVAL_SECONDS = settings.scan_interval_seconds
THREAT_STATUSES = settings.threat_statuses


# --------------------------------------------------------------------------
# Server Entrypoint
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        reload_dirs=["."],
        reload_excludes=[".venv*", ".git*", "__pycache__*"],
    )
