# =============================================================================
# Net-monit V12.4 -- Windows Service Installer (standalone repair/reinstall)
# Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com
# Run as Administrator
# =============================================================================
param(
    [string]$InstallPath = "",
    [string]$PythonExe   = "",
    [string]$ServiceName = "",
    [int]$Port           = 0
)

$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "ERROR: Run as Administrator." -ForegroundColor Red; exit 1 }

# Read from registry if not supplied
function Get-Reg([string]$name, [string]$default) {
    try { return (Get-ItemProperty "HKLM:\SOFTWARE\NetMonit-V12.4" -EA SilentlyContinue).$name }
    catch { return $default }
}
if (!$InstallPath)  { $InstallPath  = Get-Reg "InstallPath" "$env:SystemDrive\NetMonit-V12.4" }
if (!$ServiceName)  { $ServiceName  = Get-Reg "ServiceName" "Net_Monit_V124" }
if ($Port -eq 0)    { $Port         = [int](Get-Reg "Port" 5050) }

$SvcScript = Join-Path $InstallPath "install_service.py"
if (-not (Test-Path $SvcScript)) {
    Write-Host "ERROR: install_service.py not found at $SvcScript" -ForegroundColor Red; exit 1
}

# Auto-detect Python
if (!$PythonExe) {
    $candidates = @(
        (Join-Path $InstallPath "venv\Scripts\pythonw.exe"),
        (Join-Path $InstallPath "venv\Scripts\python.exe")
    )
    foreach ($c in $candidates) { if (Test-Path $c) { $PythonExe = $c; break } }
    if (!$PythonExe) {
        $found = Get-Command python -ErrorAction SilentlyContinue
        if ($found) { $PythonExe = $found.Source }
    }
}
if (!$PythonExe -or !(Test-Path $PythonExe)) {
    Write-Host "ERROR: Python not found." -ForegroundColor Red; exit 1
}

Write-Host ""
Write-Host "  Net-monit V12.4 Service Installer" -ForegroundColor Cyan
Write-Host "  ===================================" -ForegroundColor Cyan
Write-Host "  Install path : $InstallPath"
Write-Host "  Python       : $PythonExe"
Write-Host "  Service name : $ServiceName"
Write-Host "  Port         : $Port"
Write-Host ""

# pywin32 post-install
Write-Host "Step 1/4  pywin32 post-install..." -ForegroundColor Yellow
$pyDir = Split-Path $PythonExe -Parent
foreach ($pi in @("$pyDir\pywin32_postinstall.py","$pyDir\..\Scripts\pywin32_postinstall.py")) {
    $pi = [IO.Path]::GetFullPath($pi)
    if (Test-Path $pi) {
        & $PythonExe $pi -install 2>$null
        Write-Host "          Ran: $pi" -ForegroundColor Green
        break
    }
}

# Remove old service
Write-Host "Step 2/4  Removing old registration..." -ForegroundColor Yellow
& sc.exe stop   $ServiceName 2>$null | Out-Null
Start-Sleep 2
& sc.exe delete $ServiceName 2>$null | Out-Null
Start-Sleep 1

# Register
Write-Host "Step 3/4  Registering service..." -ForegroundColor Yellow
Set-Location $InstallPath
$env:NETMON_PORT        = "$Port"
$env:NETMON_SVC_NAME    = $ServiceName
$env:NETMON_SVC_DISPLAY = "Net-monit V12.4 Network Monitor"
$result = & $PythonExe $SvcScript install 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Registration failed." -ForegroundColor Red
    $result | ForEach-Object { Write-Host "  $_" }
    exit 1
}
Write-Host "          Registered (Automatic Delayed Start)" -ForegroundColor Green

# Start and wait
Write-Host "Step 4/4  Starting service..." -ForegroundColor Yellow
& sc.exe start $ServiceName | Out-Null
$running = $false
for ($i = 0; $i -lt 18; $i++) {
    Start-Sleep 2
    $q = & sc.exe query $ServiceName 2>&1 | Out-String
    if ($q -match "RUNNING") { $running = $true; break }
    if ($i % 3 -eq 2) { Write-Host "          Waiting... $(($i+1)*2)s" }
}

Write-Host ""
if ($running) {
    Write-Host "  SUCCESS: Service RUNNING" -ForegroundColor Green
    Write-Host "  Dashboard: http://localhost:$Port" -ForegroundColor Cyan
    Write-Host "  First-run token: see $InstallPath\data\FIRST-RUN-ADMIN-TOKEN.txt" -ForegroundColor Yellow
    Write-Host "  (email: admin@email.com -- token is unique to this install)" -ForegroundColor Yellow
} else {
    Write-Host "  Service installed but not yet RUNNING." -ForegroundColor Yellow
    Write-Host "  Debug: python install_service.py debug" -ForegroundColor Gray
    $log = Join-Path $InstallPath "logs\service.log"
    if (Test-Path $log) { Get-Content $log -Tail 8 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray } }
}
Write-Host ""
