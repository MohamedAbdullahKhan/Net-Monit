# =============================================================================
# Net-monit V12.4 - Install weekly purge scheduled task (Windows)
# Run once in an elevated (Administrator) PowerShell.
# =============================================================================
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$PurgeScript = Join-Path $ScriptDir "purge_old_data.py"
$Python      = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $Python) { $Python = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $Python) { Write-Error "Python not found in PATH"; exit 1 }
$LogFile     = Join-Path $ScriptDir "..\data\purge.log"
$LogFile     = (Resolve-Path $LogFile -ErrorAction SilentlyContinue) ?? $LogFile

$Action  = New-ScheduledTaskAction -Execute $Python `
             -Argument "`"$PurgeScript`" --vacuum >> `"$LogFile`" 2>&1"
$Trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Sunday -At "03:00"
$Settings= New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false

Register-ScheduledTask `
  -TaskName   "NetMonit-WeeklyPurge" `
  -Action     $Action `
  -Trigger    $Trigger `
  -Settings   $Settings `
  -RunLevel   Highest `
  -Force

Write-Host "- Scheduled task 'NetMonit-WeeklyPurge' installed." -ForegroundColor Green
Write-Host "  Runs every Sunday at 03:00."
Write-Host "  Log: $LogFile"
Write-Host ""
Write-Host "  To verify:  Get-ScheduledTask -TaskName NetMonit-WeeklyPurge"
Write-Host "  To remove:  Unregister-ScheduledTask -TaskName NetMonit-WeeklyPurge"
