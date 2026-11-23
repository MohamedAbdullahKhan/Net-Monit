# Net-monit V12.4 -- Npcap installer helper (called by Setup.bat / the wizards)
# WHY THIS IS NOT 100% SILENT FOR EVERYONE:
#   Npcap's silent switch (/S) exists ONLY in the paid "Npcap OEM" edition. The free edition (the only one that can be
#   downloaded) has no silent mode, may not be redistributed inside another product, and is licensed for 5 systems.
# WHAT THIS SCRIPT DOES (in this order):
#   1. Npcap already installed            -> nothing to do.
#   2. setup\deps\npcap-*oem*.exe present -> installs fully SILENT (/S).   <- bring your OEM installer, hands-off.
#   3. otherwise downloads the newest free installer from npcap.com (checks the Authenticode signature) and starts it
#      with Npcap's wizard visible: Agree -> Install -> Next -> Finish (4 clicks). Setup waits and continues.
#   4. If anything fails Net-monit still works: Windows capture is built in (raw sockets). Npcap only adds MAC addresses,
#      VLAN tags and full BPF filters.
param([switch]$SkipIfMissing, [switch]$Quiet, [string]$DepsDir = (Join-Path $PSScriptRoot "deps"))
$ErrorActionPreference = "Stop"
function Say($m, $c = "Gray") { if (-not $Quiet) { Write-Host "[Npcap] $m" -ForegroundColor $c } }

function Test-Npcap {
    if (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll") { return $true }
    if (Get-Service -Name npcap -ErrorAction SilentlyContinue) { return $true }
    return [bool](Get-ItemProperty "HKLM:\SOFTWARE\Npcap" -ErrorAction SilentlyContinue)
}

if (Test-Npcap) { Say "already installed - OK" "Green"; exit 0 }
if ($SkipIfMissing) { Say "not installed (skipped)" "Yellow"; exit 0 }

# --- 2. OEM installer supplied by the user: real silent install ---------------------------------------------------
$oem = Get-ChildItem -Path $DepsDir -Filter "npcap*oem*.exe" -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
if ($oem) {
    Say "OEM installer found ($($oem.Name)) - installing silently..."
    $p = Start-Process -FilePath $oem.FullName -ArgumentList "/S","/winpcap_mode=no","/loopback_support=yes","/dot11_support=no" -Wait -PassThru
    if ((Test-Npcap)) { Say "installed silently - OK" "Green"; exit 0 }
    Say "OEM installer exit code $($p.ExitCode); falling back to the guided installer" "Yellow"
}

# --- 3. free edition: download newest + signature check + visible wizard ---------------------------------------
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $exe = Get-ChildItem -Path $DepsDir -Filter "npcap-*.exe" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "oem" } | Sort-Object Name -Descending | Select-Object -First 1
    if ($exe) { $file = $exe.FullName; Say "using local installer $($exe.Name)" }
    else {
        $html = (Invoke-WebRequest -Uri "https://npcap.com/" -UseBasicParsing -TimeoutSec 30).Content
        $m = [regex]::Matches($html, 'dist/npcap-(\d+(?:\.\d+)+)\.exe') | Select-Object -First 1
        $url = if ($m) { "https://npcap.com/" + $m.Value } else { "https://npcap.com/dist/npcap-1.80.exe" }
        $file = Join-Path $env:TEMP ([IO.Path]::GetFileName($url))
        Say "downloading $url"
        Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing -TimeoutSec 300
    }
    $sig = Get-AuthenticodeSignature $file
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "Nmap|Insecure") {
        throw "signature check failed ($($sig.Status)) - refusing to run an unsigned/foreign installer"
    }
    Say "signature OK. Npcap's own installer opens now: click  I Agree > Install > Next > Finish." "Cyan"
    Say "(Free edition has no silent mode - this is Npcap's licence, not a Net-monit limit. Free licence: max 5 systems.)" "Yellow"
    Start-Process -FilePath $file -ArgumentList "/winpcap_mode=no","/loopback_support=yes" -Wait
    if (Test-Npcap) { Say "installed - OK" "Green"; exit 0 }
    Say "Npcap not detected after the installer closed (cancelled?). Continuing: built-in capture still works." "Yellow"
} catch {
    Say "could not install Npcap: $($_.Exception.Message)" "Yellow"
    Say "Continuing without it: built-in Windows capture works; install Npcap later from https://npcap.com" "Yellow"
}
exit 0
