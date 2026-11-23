@echo off
setlocal EnableDelayedExpansion
title Net-monit V12.4 Uninstaller

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c \"%~s0\"' -Verb RunAs"
    exit /b
)

echo.
echo  ======================================================
echo   Net-monit V12.4 Uninstaller
echo   Copyright (c) 2024-2026 Abdullah-InfoXtek.com
echo  ======================================================
echo.
echo  This will STOP and REMOVE the Net-monit V12.4 service.
echo  Your data in the data\ folder will be preserved.
echo.
set /p CONFIRM=Type YES to continue: 
if /i "!CONFIRM!" neq "YES" (echo Cancelled. & pause & exit /b 0)

:: Read install path and python from registry
set "IP="
set "PY=python"
set "SVC=Net_Monit_V124"

for /f "tokens=2*" %%A in ('reg query "HKLM\SOFTWARE\NetMonit-V12.4" /v InstallPath 2^>nul') do set "IP=%%B"
for /f "tokens=2*" %%A in ('reg query "HKLM\SOFTWARE\NetMonit-V12.4" /v PythonExe 2^>nul') do set "PY=%%B"
for /f "tokens=2*" %%A in ('reg query "HKLM\SOFTWARE\NetMonit-V12.4" /v ServiceName 2^>nul') do set "SVC=%%B"

if "!IP!"=="" set "IP=%~dp0"
echo [Uninstall] Path    : !IP!
echo [Uninstall] Service : !SVC!
echo [Uninstall] Python  : !PY!
echo.

:: Stop service
echo [Uninstall] Stopping service...
net stop "!SVC!" >nul 2>&1
timeout /t 3 /nobreak >nul

:: Remove via install_service.py
set "SVC_SCRIPT=!IP!install_service.py"
if exist "!SVC_SCRIPT!" (
    echo [Uninstall] Removing service registration...
    cd /d "!IP!"
    "!PY!" "!SVC_SCRIPT!" remove >nul 2>&1
) else (
    echo [Uninstall] Removing via sc.exe...
    sc delete "!SVC!" >nul 2>&1
)
timeout /t 2 /nobreak >nul

:: Remove firewall rules
echo [Uninstall] Removing firewall rules...
for /f "tokens=*" %%R in ('netsh advfirewall firewall show rule name^=all ^| findstr "Net-monit V12.4"') do (
    netsh advfirewall firewall delete rule name="%%R" >nul 2>&1
)
netsh advfirewall firewall delete rule name="Net-monit V12.4 Port 5050" >nul 2>&1

:: Remove registry
echo [Uninstall] Cleaning registry...
reg delete "HKLM\SOFTWARE\NetMonit-V12.4" /f >nul 2>&1

:: Remove desktop shortcut
set "DESK=%USERPROFILE%\Desktop\Net-monit Dashboard.url"
if exist "!DESK!" (del /f /q "!DESK!" >nul 2>&1 && echo [Uninstall] Desktop shortcut removed.)

echo.
echo  ======================================================
echo   Net-monit V12.4 service removed.
echo   Data preserved at: !IP!data\
echo   To fully remove files: delete folder !IP!
echo  ======================================================
echo.
pause
endlocal
