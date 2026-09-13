@echo off
title ShadowMem SOC Launcher
cd /d "%~dp0"

echo [*] Activating ShadowMem virtual environment...
call .venv\Scripts\activate.bat

echo [*] Opening ShadowMem Cyber Defense Dashboard...
start http://127.0.0.1:8000

echo [*] Starting Uvicorn backend server...
python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
pause