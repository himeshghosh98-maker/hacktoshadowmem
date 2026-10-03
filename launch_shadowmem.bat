@echo off
title ShadowMem SOC Launcher
cd /d "%~dp0"
REM ---------------------------------------------------------------
REM ARCHITECTURE: app.py is the SINGLE AUTHORITATIVE SERVER.
REM It serves the main dashboard UI, real memory-scan endpoints,
REM WebSocket alerts (/ws/alerts), and /simulate/alert.
REM Do NOT run server.py here — it is a mock/testing stub only.
REM ---------------------------------------------------------------

echo [*] Activating ShadowMem virtual environment...
call .venv\Scripts\activate.bat

echo [*] Opening ShadowMem Cyber Defense Dashboard...
start http://127.0.0.1:8000

echo [*] Starting Uvicorn backend server...
python -m uvicorn app:app --reload --reload-dir . --reload-exclude ".venv" --reload-exclude ".git" --host 127.0.0.1 --port 8000
pause  