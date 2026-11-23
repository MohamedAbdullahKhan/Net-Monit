# Net-monit V12.4 -- Uninstaller
param([string]$InstallPath = "")
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run as Administrator." -ForegroundColor Red; exit 1
}
$ServiceName = "Net_Monit_V124"
if ([string]::IsNullOrEmpty($InstallPath)) {
    try { $InstallPath = (Get-ItemProperty "HKLM:\SOFTWARE\NetMonit-V12.4" -ErrorAction SilentlyContinue).InstallPath } catch {}
}
Write-Host "Stopping and removing Net-monit V12.4..." -ForegroundColor Yellow
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne "Stopped") { Stop-Service $ServiceName -Force }
    $py = if ($InstallPath) { Join-Path $InstallPath "venv\Scripts\python.exe" } else { "python" }
    if (-not (Test-Path $py)) { $py = "python" }
    $svcScript = if ($InstallPath) { Join-Path $InstallPath "install_service.py" } else { "install_service.py" }
    if (Test-Path $svcScript) { & $py $svcScript remove 2>$null }
    Write-Host "Service removed." -ForegroundColor Green
} else {
    Write-Host "Service not installed." -ForegroundColor Yellow
}
try { Remove-Item -Path "HKLM:\SOFTWARE\NetMonit-V12.4" -Recurse -Force -ErrorAction SilentlyContinue } catch {}
Write-Host "Done. Data preserved at: $InstallPath\data\" -ForegroundColor Green
