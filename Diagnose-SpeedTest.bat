@echo off
cd /d "%~dp0"
set "PY="
if exist "venv\Scripts\python.exe" set "PY=venv\Scripts\python.exe"
if not defined PY ( where py >nul 2>&1 && set "PY=py -3" )
if not defined PY set "PY=python"
%PY% scripts\diagnose_speedtest.py
echo.
pause
