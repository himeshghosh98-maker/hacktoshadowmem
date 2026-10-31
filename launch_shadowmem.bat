@echo off
title ShadowMem SOC Launcher
cd /d "%~dp0"
REM ---------------------------------------------------------------
REM ARCHITECTURE: app.py is the SINGLE AUTHORITATIVE SERVER.
REM It serves the main dashboard UI, real memory-scan endpoints,
REM WebSocket alerts (/ws/alerts), and /simulate/alert.
REM
REM The bind host/port are resolved from the centralized configuration
REM (core/config.py, which reads .env and SHADOWMEM_* environment
REM variables), so the launched server and the browser URL always agree.
REM Override with e.g. SET SHADOWMEM_PORT=8765 before launching.
REM ---------------------------------------------------------------

if not exist ".env" (
    if exist ".env.example" (
        echo [*] Initializing .env from .env.example...
        copy .env.example .env >nul
    )
)

if not exist ".venv\Scripts\activate.bat" (
    echo [*] ShadowMem virtual environment not detected. Creating .venv...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    echo [*] Installing dependencies from requirements.txt...
    pip install -r requirements.txt
) else (
    echo [*] Activating ShadowMem virtual environment...
    call .venv\Scripts\activate.bat
)

echo [*] Resolving bind host/port from core/config.py (.env + SHADOWMEM_* env vars)...
for /f "usebackq delims=" %%p in (`python -c "from core.config import settings; print(settings.port)"`) do set "APP_BIND_PORT=%%p"
for /f "usebackq delims=" %%h in (`python -c "from core.config import settings; print(settings.host)"`) do set "APP_BIND_HOST=%%h"

if not defined APP_BIND_PORT (
    echo [!] Could not resolve the port from core/config.py - falling back to 8000.
    set "APP_BIND_PORT=8000"
)

REM The wildcard bind address is not navigable in a browser, and this local
REM SOC dashboard should not be exposed on every interface. Keep loopback
REM unless a concrete interface was configured (e.g. SHADOWMEM_HOST=192.168.1.5).
if not defined APP_BIND_HOST set "APP_BIND_HOST=0.0.0.0"
if "%APP_BIND_HOST%"=="0.0.0.0" set "APP_BIND_HOST=127.0.0.1"
if "%APP_BIND_HOST%"=="::" set "APP_BIND_HOST=127.0.0.1"

echo [*] Opening ShadowMem Cyber Defense Dashboard at http://%APP_BIND_HOST%:%APP_BIND_PORT% ...
start http://%APP_BIND_HOST%:%APP_BIND_PORT%

echo [*] Starting Uvicorn backend server on %APP_BIND_HOST%:%APP_BIND_PORT% ...
python -m uvicorn app:app --reload --reload-dir . --reload-exclude ".venv" --reload-exclude ".git" --host %APP_BIND_HOST% --port %APP_BIND_PORT%
pause
