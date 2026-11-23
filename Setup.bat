@echo off
setlocal EnableDelayedExpansion
title Net-monit V12.4 Setup Wizard

echo.
echo  ======================================================
echo   Net-monit V12.4 Setup Wizard
echo   Copyright (c) 2024-2026 Abdullah-InfoXtek.com
echo   Contact: abuabdullah.be@outlook.com
echo   Default port: 5050
echo  ======================================================
echo.

REM ---- Auto-elevate if not admin ----------------------------------------
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo [Setup] Requesting Administrator privileges...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c \"%~s0\"' -Verb RunAs"
    exit /b
)
echo [Setup] Running as Administrator - OK
echo.

set "ROOT=%~dp0"
set "WIZARD=%ROOT%setup\setup_wizard.py"
set "PS_WIZARD=%ROOT%setup\Setup-Windows.ps1"

echo [Setup] Looking for Python interpreter...
echo.

REM ---- Simple sequential Python detection (no nested for-loops) --------
REM Windows ships fake python.exe/python3.exe "App Execution Alias" stubs
REM in ...\AppData\Local\Microsoft\WindowsApps\ that only redirect to the
REM Microsoft Store -- and that folder is often placed ahead of a real
REM Python install in PATH by default. A bare "--version" exit-code check
REM isn't always enough to catch this reliably, so each candidate's
REM resolved path is also checked and rejected if it points there.
set "PY="

python --version >nul 2>&1
if "%errorlevel%"=="0" (
    for /f "delims=" %%W in ('where python 2^>nul') do (
        echo %%W | findstr /i "WindowsApps" >nul
        if errorlevel 1 (
            set "PY=python"
            echo [Setup] Found: python
            goto :PYFOUND
        )
    )
)

python3 --version >nul 2>&1
if "%errorlevel%"=="0" (
    for /f "delims=" %%W in ('where python3 2^>nul') do (
        echo %%W | findstr /i "WindowsApps" >nul
        if errorlevel 1 (
            set "PY=python3"
            echo [Setup] Found: python3
            goto :PYFOUND
        )
    )
)

py --version >nul 2>&1
if "%errorlevel%"=="0" (
    set "PY=py"
    echo [Setup] Found: py launcher
    goto :PYFOUND
)

echo [Setup] Python was not found on this system.
echo.
goto :NOPYTHON

:PYFOUND
echo [Setup] Using Python command: %PY%
echo.
goto :LAUNCHWIZARD

:NOPYTHON
echo [Setup] Attempting to download and install Python 3.11 automatically...
echo [Setup] This requires an internet connection and may take a minute.
echo.
set "PY_INST=%TEMP%\python-3.11.9-amd64.exe"

powershell -NoProfile -ExecutionPolicy Bypass -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -OutFile '%PY_INST%' -UseBasicParsing; Write-Host 'DOWNLOAD_OK' } catch { Write-Host 'DOWNLOAD_FAILED'; Write-Host $_.Exception.Message }"

if not exist "%PY_INST%" (
    echo.
    echo [ERROR] Could not download Python installer.
    echo         Please install Python 3.9 or later manually from:
    echo         https://www.python.org/downloads/
    echo         Then run Setup.bat again.
    echo.
    pause
    endlocal
    exit /b 1
)

echo [Setup] Download complete. Installing Python 3.11 silently...
echo [Setup] Please wait, this can take 1-2 minutes...
"%PY_INST%" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1
timeout /t 5 /nobreak >nul

REM Refresh PATH for this session from the machine environment
for /f "usebackq tokens=2,*" %%A in (`reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul`) do set "PATH=%%B;%PATH%"

python --version >nul 2>&1
if "%errorlevel%"=="0" (
    set "PY=python"
    echo [Setup] Python 3.11 installed successfully.
    echo.
    goto :LAUNCHWIZARD
)

echo.
echo [ERROR] Python installation completed but python.exe is still not
echo         reachable in this session. Please CLOSE this window,
echo         open a NEW Command Prompt, and run Setup.bat again.
echo.
pause
endlocal
exit /b 1

:LAUNCHWIZARD
REM ---- V12.4: required app #2 = Npcap (packet capture add-on). Silent with an OEM installer in setup\deps, otherwise guided.
if exist "%ROOT%setup\Install-Npcap.ps1" (
    echo [Setup] Checking Npcap ^(packet capture driver^)...
    powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%setup\Install-Npcap.ps1"
    echo.
)
if not exist "%WIZARD%" (
    echo [ERROR] Setup wizard script not found at:
    echo         %WIZARD%
    echo.
    echo Trying PowerShell fallback wizard instead...
    goto :PSWIZARD
)

echo [Setup] Launching Net-monit V12.4 Setup Wizard...
echo [Setup] A window should open shortly. If nothing appears in
echo [Setup] a few seconds, check for errors printed below.
echo.
"%PY%" "%WIZARD%"
set "RC=%errorlevel%"
echo.
if "%RC%"=="0" (
    echo [Setup] Installation completed successfully.
) else (
    echo [Setup] Wizard exited with code %RC%.
    echo [Setup] If a Python error is shown above, please share it for support.
)
echo.
pause
endlocal
exit /b %RC%

:PSWIZARD
where powershell >nul 2>&1
if not "%errorlevel%"=="0" (
    echo [ERROR] Neither the Python wizard nor PowerShell is available.
    echo         Cannot continue. Please re-extract the Net-monit package.
    pause
    endlocal
    exit /b 1
)
if not exist "%PS_WIZARD%" (
    echo [ERROR] No setup wizard found anywhere in this package.
    echo         Expected: %WIZARD%
    echo         Expected: %PS_WIZARD%
    echo         Please re-download/re-extract Net-monit V12.4.
    pause
    endlocal
    exit /b 1
)
echo [Setup] Launching PowerShell setup wizard (fallback)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_WIZARD%"
set "RC=%errorlevel%"
echo.
if "%RC%"=="0" (echo [Setup] Completed.) else (echo [Setup] Exited with code %RC%.)
pause
endlocal
exit /b %RC%
