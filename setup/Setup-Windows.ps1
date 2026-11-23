# =============================================================================
# Net-monit V12.4 -- Windows Setup Wizard
# Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com
# Contact: abuabdullah.be@outlook.com
# Run as Administrator
# =============================================================================
# PARSER-SAFE: No Unicode bullet chars. No here-strings with special chars.
# No global Next handler. Per-page handler ownership model.
# =============================================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ============================================================
# STATE
# ============================================================
$script:Page          = 0
$script:nextHandler   = $null
$script:backHandler   = $null
$script:Config = @{
    AppVersion    = "10.0"
    InstallPath   = "C:\NetMonit-V12.4"
    Port          = 5050
    PythonExe     = ""
    PythonVersion = ""
    ServiceName   = "Net_Monit_V124"
    VenvEnabled   = $true
    Firewall      = $true
    AutoStart     = $true
    Desktop       = $true
}

# ============================================================
# NAVIGATION ENGINE  (one active handler at a time)
# ============================================================
function Set-Next([scriptblock]$h) {
    if ($null -ne $script:nextHandler) {
        try { $btnNext.Remove_Click($script:nextHandler) } catch {}
    }
    $script:nextHandler = $h
    if ($h) { $btnNext.Add_Click($h) }
}

function Set-Back([scriptblock]$h) {
    if ($null -ne $script:backHandler) {
        try { $btnBack.Remove_Click($script:backHandler) } catch {}
    }
    $script:backHandler = $h
    if ($h) { $btnBack.Add_Click($h) }
}

function Clear-Page {
    $pnlContent.Controls.Clear()
    $btnNext.Enabled = $true
    $btnBack.Enabled = $true
    $btnNext.Text    = "Next >"
    [Windows.Forms.Application]::DoEvents()
}

# ============================================================
# STEP INDICATOR
# ============================================================
$STEPS = @("1 Welcome","2 Python","3 License","4 Location","5 Options","6 Install","7 Finish")
$script:stepLbls = @()

function Set-Step([int]$idx) {
    for ($i = 0; $i -lt $script:stepLbls.Count; $i++) {
        if ($i -eq $idx) {
            $script:stepLbls[$i].BackColor = [Drawing.Color]::FromArgb(0,120,215)
            $script:stepLbls[$i].ForeColor = [Drawing.Color]::White
            $script:stepLbls[$i].Font      = New-Object Drawing.Font("Segoe UI", 9, [Drawing.FontStyle]::Bold)
        } else {
            $script:stepLbls[$i].BackColor = [Drawing.Color]::FromArgb(30,30,40)
            $script:stepLbls[$i].ForeColor = [Drawing.Color]::FromArgb(130,130,150)
            $script:stepLbls[$i].Font      = New-Object Drawing.Font("Segoe UI", 9)
        }
    }
}

# ============================================================
# UI HELPERS
# ============================================================
function New-H1([string]$text) {
    $l = New-Object Windows.Forms.Label
    $l.Text      = $text
    $l.Font      = New-Object Drawing.Font("Segoe UI", 16, [Drawing.FontStyle]::Bold)
    $l.ForeColor = [Drawing.Color]::White
    $l.AutoSize  = $true
    $l.Location  = New-Object Drawing.Point(28, 24)
    return $l
}

function New-Body([string]$text, [int]$y, [int]$h = 280) {
    $l = New-Object Windows.Forms.Label
    $l.Text      = $text
    $l.Font      = New-Object Drawing.Font("Segoe UI", 10)
    $l.ForeColor = [Drawing.Color]::FromArgb(190,190,205)
    $l.AutoSize  = $false
    $l.Size      = New-Object Drawing.Size(640, $h)
    $l.Location  = New-Object Drawing.Point(28, $y)
    return $l
}

function New-Lbl([string]$text, [int]$x, [int]$y, $color = $null) {
    $l = New-Object Windows.Forms.Label
    $l.Text      = $text
    $l.Font      = New-Object Drawing.Font("Segoe UI", 9)
    $l.ForeColor = if ($color) { $color } else { [Drawing.Color]::FromArgb(160,160,180) }
    $l.AutoSize  = $true
    $l.Location  = New-Object Drawing.Point($x, $y)
    return $l
}

function New-TxtBox([int]$x, [int]$y, [int]$w = 400, [string]$text = "") {
    $t = New-Object Windows.Forms.TextBox
    $t.Text        = $text
    $t.Font        = New-Object Drawing.Font("Consolas", 10)
    $t.ForeColor   = [Drawing.Color]::White
    $t.BackColor   = [Drawing.Color]::FromArgb(32,32,42)
    $t.BorderStyle = "FixedSingle"
    $t.Size        = New-Object Drawing.Size($w, 28)
    $t.Location    = New-Object Drawing.Point($x, $y)
    return $t
}

function New-ChkBox([string]$text, [int]$x, [int]$y, [bool]$chk = $true) {
    $c = New-Object Windows.Forms.CheckBox
    $c.Text      = $text
    $c.Font      = New-Object Drawing.Font("Segoe UI", 9.5)
    $c.ForeColor = [Drawing.Color]::White
    $c.AutoSize  = $true
    $c.Checked   = $chk
    $c.Location  = New-Object Drawing.Point($x, $y)
    return $c
}

function New-Btn2([string]$text, [int]$x, [int]$y, [int]$w = 140, [int]$h = 32) {
    $b = New-Object Windows.Forms.Button
    $b.Text      = $text
    $b.Font      = New-Object Drawing.Font("Segoe UI", 9)
    $b.Size      = New-Object Drawing.Size($w, $h)
    $b.Location  = New-Object Drawing.Point($x, $y)
    $b.FlatStyle = "Flat"
    $b.BackColor = [Drawing.Color]::FromArgb(45,45,60)
    $b.ForeColor = [Drawing.Color]::White
    $b.FlatAppearance.BorderColor = [Drawing.Color]::FromArgb(70,70,90)
    $b.Cursor    = [Windows.Forms.Cursors]::Hand
    return $b
}

# ============================================================
# PAGE 0 - WELCOME
# ============================================================
function Show-Welcome {
    $script:Page = 0
    Clear-Page
    Set-Step 0
    $btnBack.Enabled = $false
    Set-Back $null

    $pnlContent.Controls.Add((New-H1 "Welcome to Net-monit V12.4 Setup"))

    $lines = @(
        "This wizard installs Net-monit V12.4 on this Windows machine.",
        "",
        "Net-monit V12.4 is a production network monitoring system:",
        "  - Real-time ping, SNMP, SSH, PowerShell and disk-usage checks",
        "  - Web dashboard at http://localhost:5050",
        "  - Multi-level email alert escalation",
        "  - Per-user saved dashboard layouts (grid and list views)",
        "  - 30-day trial license with full-access activation",
        "  - Windows Service (pywin32) and Linux systemd service",
        "",
        "Requirements:",
        "  - Windows 10 / Server 2016 or later",
        "  - Python 3.9+ (will be detected or installed)",
        "  - Administrator privileges (you have them - wizard auto-elevated)",
        "",
        "Click Next to begin."
    )
    $pnlContent.Controls.Add((New-Body ($lines -join "`r`n") 74 360))

    Set-Next { Show-Python }
}

# ============================================================
# PAGE 1 - PYTHON
# ============================================================
function Show-Python {
    $script:Page = 1
    Clear-Page
    Set-Step 1
    $btnNext.Enabled = $false

    $pnlContent.Controls.Add((New-H1 "Python Environment"))
    $pnlContent.Controls.Add((New-Lbl "Checking for Python 3.9+..." 28 74))

    $statusLbl = New-Lbl "Scanning..." 28 100 ([Drawing.Color]::FromArgb(190,190,205))
    $statusLbl.AutoSize  = $false
    $statusLbl.Size      = New-Object Drawing.Size(640, 28)
    $statusLbl.Font      = New-Object Drawing.Font("Segoe UI", 10, [Drawing.FontStyle]::Bold)
    $pnlContent.Controls.Add($statusLbl)

    $detailLbl = New-Body "" 136 180
    $pnlContent.Controls.Add($detailLbl)

    $btnInstall = New-Btn2 "Install Python 3.11" 28 330
    $btnInstall.BackColor = [Drawing.Color]::FromArgb(0,100,175)
    $btnInstall.Visible   = $false
    $pnlContent.Controls.Add($btnInstall)

    $btnRetry = New-Btn2 "Retry Detection" 178 330
    $btnRetry.Visible = $false
    $pnlContent.Controls.Add($btnRetry)

    # Detect Python. Windows ships fake python.exe/python3.exe "App
    # Execution Alias" stubs in ...\AppData\Local\Microsoft\WindowsApps\
    # that only redirect to the Microsoft Store -- and that folder is
    # often placed ahead of a real Python install in PATH by default.
    # Reject any candidate that resolves there and keep looking; never
    # fall back to a bare unresolved command name (that string can later
    # get independently re-resolved by Windows to the same broken stub).
    $found = $false
    $pyExe = ""
    $pyVer = ""
    foreach ($cmd in @("python","python3","py")) {
        try {
            $raw = (& $cmd --version 2>&1) | Out-String
            if ($raw -match "Python (\d+)\.(\d+)") {
                if ([int]$Matches[1] -ge 3 -and [int]$Matches[2] -ge 9) {
                    $path = (Get-Command $cmd -ErrorAction SilentlyContinue)
                    if (-not $path) { continue }
                    if ($path.Source -match "WindowsApps") { continue }
                    $pyExe = $path.Source
                    $pyVer = $raw.Trim()
                    $found = $true
                    break
                }
            }
        } catch {}
    }

    if ($found) {
        $script:Config.PythonExe     = $pyExe
        $script:Config.PythonVersion = $pyVer
        $statusLbl.Text      = "Python detected -- ready."
        $statusLbl.ForeColor = [Drawing.Color]::FromArgb(50,200,90)
        $detailLbl.Text      = "Executable : $pyExe`r`nVersion    : $pyVer`r`n`r`nPython 3.9+ requirement met. Dependencies will be installed automatically."
        $btnNext.Enabled     = $true
        Set-Next { Show-License }
    } else {
        $statusLbl.Text      = "Python 3.9+ not found."
        $statusLbl.ForeColor = [Drawing.Color]::FromArgb(240,160,30)
        $detailLbl.Text      = "Python 3.9 or later is required.`r`n`r`nClick 'Install Python 3.11' to download and install automatically,`r`nor install manually from python.org (add to PATH), then click Retry."
        $btnInstall.Visible  = $true
        $btnRetry.Visible    = $true

        $btnRetry.Add_Click({ Show-Python })

        $btnInstall.Add_Click({
            $btnInstall.Enabled = $false
            $btnRetry.Enabled   = $false
            $statusLbl.Text     = "Downloading Python 3.11..."
            $statusLbl.ForeColor = [Drawing.Color]::FromArgb(190,190,205)
            [Windows.Forms.Application]::DoEvents()
            try {
                $url  = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
                $dest = "$env:TEMP\python-3.11.9-amd64.exe"
                (New-Object Net.WebClient).DownloadFile($url, $dest)
                $statusLbl.Text = "Installing Python 3.11 (silent)..."
                [Windows.Forms.Application]::DoEvents()
                $p = Start-Process $dest -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1" -Wait -PassThru
                if ($p.ExitCode -eq 0) {
                    $statusLbl.Text      = "Python 3.11 installed. Click Next."
                    $statusLbl.ForeColor = [Drawing.Color]::FromArgb(50,200,90)
                    # Re-resolve for real rather than assuming "python" will
                    # work -- the WindowsApps Store stub can still shadow
                    # it in PATH even right after a successful install.
                    # Refresh PATH in this process first, then prefer "py"
                    # (the official launcher, never aliased to the stub).
                    $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User")
                    $resolvedExe = "python"
                    foreach ($cmd in @("py","python")) {
                        $c = (Get-Command $cmd -ErrorAction SilentlyContinue)
                        if ($c -and $c.Source -notmatch "WindowsApps") { $resolvedExe = $c.Source; break }
                    }
                    $script:Config.PythonExe     = $resolvedExe
                    $script:Config.PythonVersion = "Python 3.11.9"
                    $btnNext.Enabled     = $true
                    Set-Next { Show-License }
                } else {
                    throw "Installer exited with code $($p.ExitCode)"
                }
            } catch {
                $statusLbl.Text      = "Installation failed: $($_.Exception.Message)"
                $statusLbl.ForeColor = [Drawing.Color]::FromArgb(255,80,80)
                $btnInstall.Enabled  = $true
                $btnRetry.Enabled    = $true
            }
        })
    }

    Set-Back { Show-Welcome }
}

# ============================================================
# PAGE 2 - LICENSE
# ============================================================
function Show-License {
    $script:Page = 2
    Clear-Page
    Set-Step 2
    $btnNext.Enabled = $false

    $pnlContent.Controls.Add((New-H1 "License Agreement"))
    $pnlContent.Controls.Add((New-Lbl "Read and accept the terms to continue." 28 74))

    $rtb = New-Object Windows.Forms.RichTextBox
    $rtb.ReadOnly    = $true
    $rtb.BorderStyle = "FixedSingle"
    $rtb.ScrollBars  = "Vertical"
    $rtb.BackColor   = [Drawing.Color]::FromArgb(22,22,30)
    $rtb.ForeColor   = [Drawing.Color]::FromArgb(190,190,205)
    $rtb.Font        = New-Object Drawing.Font("Consolas", 8.5)
    $rtb.Size        = New-Object Drawing.Size(640, 290)
    $rtb.Location    = New-Object Drawing.Point(28, 96)

    # EULA as plain string array (NO here-string to avoid parser issues)
    $eulaLines = @(
        "NET-MONIT V12.4 - END USER LICENSE AGREEMENT",
        "Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com",
        "Contact: abuabdullah.be@outlook.com",
        "",
        "IMPORTANT - READ BEFORE INSTALLING",
        "",
        "1. GRANT OF LICENSE",
        "   Abdullah-InfoXtek.com grants you a non-exclusive, non-transferable",
        "   license to install and use Net-monit V12.4 for internal network",
        "   monitoring on machines you own or operate.",
        "",
        "2. FREE SOFTWARE",
        "   Net-monit is provided FREE of charge for personal and business use.",
        "   You must NOT sell, resell, or commercially redistribute this software.",
        "   If you wish to distribute, you must first contact the author.",
        "",
        "3. CONTACT FOR LICENSE KEY",
        "   This software is free but requires a license key after the 30-day",
        "   trial. To obtain your free license key, contact:",
        "     Email   : abuabdullah.be@outlook.com",
        "     Website : Abdullah-InfoXtek.com",
        "   Share your Device ID and Activation Code from the Settings page.",
        "",
        "4. RESTRICTIONS",
        "   You may NOT:",
        "   a) Sell or commercially redistribute this software",
        "   b) Reverse-engineer or decompile the software",
        "   c) Remove copyright notices",
        "   d) Use for unlawful network surveillance",
        "",
        "5. COPYRIGHT",
        "   Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com",
        "   All rights reserved.",
        "",
        "6. DISCLAIMER",
        "   THE SOFTWARE IS PROVIDED AS IS WITHOUT WARRANTY OF ANY KIND.",
        "   IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DAMAGES.",
        "",
        "By checking the box below you confirm you have READ, UNDERSTOOD,",
        "and AGREE to be bound by all terms of this License Agreement."
    )
    $rtb.Text = $eulaLines -join "`r`n"
    $pnlContent.Controls.Add($rtb)

    $chk = New-Object Windows.Forms.CheckBox
    $chk.Text      = "I have read and agree to the terms of the License Agreement"
    $chk.Font      = New-Object Drawing.Font("Segoe UI", 9, [Drawing.FontStyle]::Bold)
    $chk.ForeColor = [Drawing.Color]::White
    $chk.AutoSize  = $true
    $chk.Checked   = $false
    $chk.Location  = New-Object Drawing.Point(28, 400)
    $pnlContent.Controls.Add($chk)

    # CRITICAL: capture handler in local var before closure to avoid scope issues
    $navToLocation = [scriptblock]{ Show-Location }

    $chk.Add_CheckedChanged({
        if ($chk.Checked) {
            if ($null -ne $script:nextHandler) {
                try { $btnNext.Remove_Click($script:nextHandler) } catch {}
            }
            $script:nextHandler = $navToLocation
            $btnNext.Add_Click($script:nextHandler)
            $btnNext.Enabled = $true
        } else {
            try { $btnNext.Remove_Click($navToLocation) } catch {}
            $script:nextHandler = $null
            $btnNext.Enabled = $false
        }
    })

    Set-Back { Show-Python }
}

# ============================================================
# PAGE 3 - LOCATION
# ============================================================
function Show-Location {
    $script:Page = 3
    Clear-Page
    Set-Step 3

    $pnlContent.Controls.Add((New-H1 "Installation Location"))
    $pnlContent.Controls.Add((New-Lbl "Choose where Net-monit V12.4 will be installed." 28 74))

    $pnlContent.Controls.Add((New-Lbl "Install to:" 28 110))
    $txtPath = New-TxtBox 28 132 510 $script:Config.InstallPath
    $pnlContent.Controls.Add($txtPath)

    $btnBrowse = New-Btn2 "Browse..." 548 132 90 28
    $pnlContent.Controls.Add($btnBrowse)

    $diskLbl = New-Lbl "" 28 170
    $diskLbl.AutoSize = $false
    $diskLbl.Size     = New-Object Drawing.Size(640, 20)
    $pnlContent.Controls.Add($diskLbl)

    function Update-Disk {
        try {
            $root = [IO.Path]::GetPathRoot($txtPath.Text)
            $di   = New-Object IO.DriveInfo($root)
            $free = [math]::Round($di.AvailableFreeSpace / 1MB)
            $diskLbl.Text = "Drive $root -- $free MB free  (Net-monit requires ~250 MB)"
        } catch { $diskLbl.Text = "" }
    }
    Update-Disk

    $pnlContent.Controls.Add((New-Lbl "Dashboard port  (default 5050):" 28 206))
    $nudPort = New-Object Windows.Forms.NumericUpDown
    $nudPort.Minimum   = 1024
    $nudPort.Maximum   = 65535
    $nudPort.Value     = $script:Config.Port
    $nudPort.Font      = New-Object Drawing.Font("Consolas", 10)
    $nudPort.BackColor = [Drawing.Color]::FromArgb(32,32,42)
    $nudPort.ForeColor = [Drawing.Color]::White
    $nudPort.Size      = New-Object Drawing.Size(120, 28)
    $nudPort.Location  = New-Object Drawing.Point(28, 228)
    $pnlContent.Controls.Add($nudPort)

    $pnlContent.Controls.Add((New-Lbl "Windows Service name:" 28 272))
    $txtSvc = New-TxtBox 28 294 240 $script:Config.ServiceName
    $pnlContent.Controls.Add($txtSvc)

    $btnBrowse.Add_Click({
        $dlg = New-Object Windows.Forms.FolderBrowserDialog
        $dlg.Description  = "Select Net-monit installation folder"
        $dlg.SelectedPath = $txtPath.Text
        if ($dlg.ShowDialog($form) -eq "OK") {
            $txtPath.Text = $dlg.SelectedPath
            Update-Disk
        }
    })

    Set-Next {
        $p = $txtPath.Text.Trim()
        $s = $txtSvc.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($p)) {
            [Windows.Forms.MessageBox]::Show("Enter a valid install path.","Setup","OK","Warning") | Out-Null
            return
        }
        if ([string]::IsNullOrWhiteSpace($s)) {
            [Windows.Forms.MessageBox]::Show("Enter a service name.","Setup","OK","Warning") | Out-Null
            return
        }
        $script:Config.InstallPath  = $p
        $script:Config.Port         = [int]$nudPort.Value
        $script:Config.ServiceName  = $s
        Show-Options
    }

    Set-Back { Show-License }
}

# ============================================================
# PAGE 4 - OPTIONS
# ============================================================
function Show-Options {
    $script:Page = 4
    Clear-Page
    Set-Step 4

    $pnlContent.Controls.Add((New-H1 "Installation Options"))
    $pnlContent.Controls.Add((New-Lbl "Configure optional components." 28 74))

    $chkVenv  = New-ChkBox "Create Python virtual environment in install folder (recommended)" 28 108 $script:Config.VenvEnabled
    $chkFw    = New-ChkBox "Add Windows Firewall rule for port $($script:Config.Port)" 28 148 $script:Config.Firewall
    $chkAuto  = New-ChkBox "Start Net-monit service automatically on Windows startup" 28 188 $script:Config.AutoStart
    $chkDesk  = New-ChkBox "Create desktop shortcut to the dashboard" 28 228 $script:Config.Desktop

    foreach ($c in @($chkVenv,$chkFw,$chkAuto,$chkDesk)) {
        $pnlContent.Controls.Add($c)
    }

    # Summary panel
    $sumPanel = New-Object Windows.Forms.Panel
    $sumPanel.BackColor = [Drawing.Color]::FromArgb(22,22,30)
    $sumPanel.Size      = New-Object Drawing.Size(640, 100)
    $sumPanel.Location  = New-Object Drawing.Point(28, 290)
    $pnlContent.Controls.Add($sumPanel)

    $sumLbl = New-Object Windows.Forms.Label
    $sumLbl.Text      = "Install path : $($script:Config.InstallPath)`r`nPort         : $($script:Config.Port)`r`nService      : $($script:Config.ServiceName)`r`nPython       : $($script:Config.PythonVersion)"
    $sumLbl.Font      = New-Object Drawing.Font("Consolas", 8.5)
    $sumLbl.ForeColor = [Drawing.Color]::FromArgb(130,130,150)
    $sumLbl.AutoSize  = $false
    $sumLbl.Size      = New-Object Drawing.Size(620, 90)
    $sumLbl.Location  = New-Object Drawing.Point(10, 6)
    $sumPanel.Controls.Add($sumLbl)

    Set-Next {
        $script:Config.VenvEnabled = $chkVenv.Checked
        $script:Config.Firewall    = $chkFw.Checked
        $script:Config.AutoStart   = $chkAuto.Checked
        $script:Config.Desktop     = $chkDesk.Checked
        Show-Install
    }

    Set-Back { Show-Location }
}

# ============================================================
# PAGE 5 - INSTALL
# ============================================================
function Show-Install {
    $script:Page = 5
    Clear-Page
    Set-Step 5
    $btnNext.Enabled = $false
    $btnBack.Enabled = $false

    $pnlContent.Controls.Add((New-H1 "Installing Net-monit V12.4"))

    $statusLbl = New-Lbl "Preparing..." 28 74 ([Drawing.Color]::FromArgb(190,190,205))
    $statusLbl.AutoSize  = $false
    $statusLbl.Size      = New-Object Drawing.Size(640, 24)
    $statusLbl.Font      = New-Object Drawing.Font("Segoe UI", 9.5)
    $pnlContent.Controls.Add($statusLbl)

    $progress = New-Object Windows.Forms.ProgressBar
    $progress.Minimum = 0; $progress.Maximum = 100; $progress.Value = 0
    $progress.Style   = "Continuous"
    $progress.Size    = New-Object Drawing.Size(640, 18)
    $progress.Location = New-Object Drawing.Point(28, 102)
    $pnlContent.Controls.Add($progress)

    $pctLbl = New-Lbl "0%" 676 105
    $pnlContent.Controls.Add($pctLbl)

    $logBox = New-Object Windows.Forms.RichTextBox
    $logBox.ReadOnly    = $true
    $logBox.BorderStyle = "None"
    $logBox.BackColor   = [Drawing.Color]::FromArgb(14,14,20)
    $logBox.ForeColor   = [Drawing.Color]::FromArgb(120,240,120)
    $logBox.Font        = New-Object Drawing.Font("Consolas", 8.5)
    $logBox.ScrollBars  = "Vertical"
    $logBox.Size        = New-Object Drawing.Size(640, 280)
    $logBox.Location    = New-Object Drawing.Point(28, 130)
    $pnlContent.Controls.Add($logBox)

    function Add-Log([string]$msg, [string]$col = "Green") {
        $ts = Get-Date -Format "HH:mm:ss"
        $line = "[$ts]  $msg"
        Write-Host $line
        $logBox.SelectionStart  = $logBox.TextLength
        $logBox.SelectionLength = 0
        $logBox.SelectionColor  = switch ($col) {
            "Red"    { [Drawing.Color]::FromArgb(255,80,80) }
            "Yellow" { [Drawing.Color]::FromArgb(240,180,30) }
            "Gray"   { [Drawing.Color]::FromArgb(100,100,120) }
            default  { [Drawing.Color]::FromArgb(100,230,100) }
        }
        $logBox.AppendText("$line`n")
        $logBox.ScrollToCaret()
        [Windows.Forms.Application]::DoEvents()
    }

    function Set-Prog([int]$pct, [string]$msg) {
        $progress.Value  = [Math]::Clamp($pct, 0, 100)
        $pctLbl.Text     = "$pct%"
        $statusLbl.Text  = $msg
        [Windows.Forms.Application]::DoEvents()
    }

    $ip = $script:Config.InstallPath
    if ($script:Config.PythonExe -and $script:Config.PythonExe -notmatch "WindowsApps") {
        $py = $script:Config.PythonExe
    } else {
        # Safety net -- detection should always have set this already, but
        # never fall back to a bare "python" string: resolve "py" (the
        # official launcher, never shadowed by the WindowsApps Store stub)
        # for real instead.
        $c  = (Get-Command "py" -ErrorAction SilentlyContinue)
        $py = if ($c) { $c.Source } else { "py" }
    }

    # STEP 1: Create directories
    Set-Prog 5 "Creating directory structure..."
    try {
        foreach ($sub in @("","data","logs","monitor\checkers","static\css","static\js","templates","scripts\windows","scripts\linux","setup","tools")) {
            $path = Join-Path $ip $sub
            if (-not (Test-Path $path)) {
                New-Item -ItemType Directory -Path $path -Force | Out-Null
            }
        }
        Add-Log "Directory structure created: $ip"
    } catch {
        Add-Log "Directory creation failed: $_" "Red"
        [Windows.Forms.MessageBox]::Show("Failed to create directory: $_","Error","OK","Error") | Out-Null
        $btnBack.Enabled = $true; return
    }

    # STEP 2: Copy files
    Set-Prog 15 "Copying application files..."
    try {
        $scriptDir = Split-Path $PSCommandPath -Parent
        $srcRoot   = Split-Path $scriptDir -Parent
        $appPy     = Join-Path $srcRoot "app.py"
        if (Test-Path $appPy) {
            $robocopyArgs = @($srcRoot, $ip, "/E", "/XD", ".git", "__pycache__", "/XF", "*.pyc", "*.zip", "/NFL", "/NDL", "/NJH", "/NJS")
            & robocopy @robocopyArgs | Out-Null
            Add-Log "Files copied from $srcRoot"
        } else {
            Add-Log "Source root not found at $srcRoot -- files not copied." "Yellow"
            Add-Log "Copy the Net-monit V12.4 folder contents manually to: $ip" "Yellow"
        }
    } catch { Add-Log "File copy warning: $_" "Yellow" }

    # STEP 3: Create/update config.yaml
    Set-Prog 28 "Writing configuration file..."
    try {
        $cfgPath = Join-Path $ip "config.yaml"
        if (-not (Test-Path $cfgPath)) {
            $cfgLines = @(
                "# Net-monit V12.4 - config.yaml",
                "smtp:",
                "  enabled: false",
                "  host: smtp-mail.outlook.com",
                "  port: 587",
                "  use_tls: true",
                "  username: ''",
                "  password: ''",
                "  from_address: ''",
                "  admin_emails: []",
                "  support_emails: []",
                "  manager_emails: []",
                "server:",
                "  port: $($script:Config.Port)",
                "  host: 0.0.0.0",
                "devices: []"
            )
            Set-Content -Path $cfgPath -Value ($cfgLines -join "`r`n") -Encoding UTF8
            Add-Log "config.yaml created (port $($script:Config.Port))"
        } else {
            Add-Log "config.yaml exists -- not overwritten" "Gray"
        }
    } catch { Add-Log "config.yaml error: $_" "Yellow" }

    # STEP 4: Virtual env
    if ($script:Config.VenvEnabled) {
        Set-Prog 38 "Creating Python virtual environment..."
        try {
            $venvPath = Join-Path $ip "venv"
            if (-not (Test-Path $venvPath)) {
                & $py -m venv $venvPath 2>&1 | Out-Null
                Add-Log "Virtual environment created: $venvPath"
            } else {
                Add-Log "Virtual environment already exists -- skipped" "Gray"
            }
            $venvPy = Join-Path $venvPath "Scripts\python.exe"
            if (Test-Path $venvPy) { $py = $venvPy }
        } catch { Add-Log "venv warning: $_" "Yellow" }
    }

    # STEP 5: pip install
    Set-Prog 50 "Installing Python dependencies..."
    try {
        $reqFile = Join-Path $ip "requirements.txt"
        if (Test-Path $reqFile) {
            $pipOut = & $py -m pip install -r $reqFile --quiet 2>&1
            if ($LASTEXITCODE -eq 0) { Add-Log "pip install complete" }
            else { Add-Log "pip install had warnings -- check manually" "Yellow" }
        } else {
            Add-Log "requirements.txt not found -- skipping pip install" "Yellow"
        }
    } catch { Add-Log "pip error: $_" "Yellow" }

    # V12.0 patch 01: prove the packages really import (a half-failed pip run used to leave a service that starts and stops at once)
    try {
        $chk = & $py -c "import flask, yaml, paramiko, apscheduler, cryptography, pysnmp, scapy, maxminddb, psutil, win32serviceutil; print('NM_IMPORT_OK')" 2>&1
        if ("$chk" -match "NM_IMPORT_OK") { Add-Log "All required Python packages are installed" }
        else {
            Add-Log ("A required Python package is missing or broken: " + ("$chk" -replace "\s+"," ")) "Red"
            Add-Log ("Fix: open Command Prompt as Administrator and run:  " + $py + " -m pip install -r " + $reqFile) "Yellow"
        }
    } catch { Add-Log "Package check warning: $_" "Yellow" }

    # STEP 5b (V12.4): Npcap (optional; silent only with an OEM installer in setup\deps, otherwise guided)
    try {
        $nps = Join-Path $PSScriptRoot "Install-Npcap.ps1"
        if (Test-Path $nps) { Set-Prog 60 "Checking Npcap..."; & powershell -NoProfile -ExecutionPolicy Bypass -File $nps -Quiet | Out-Null
            if (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll") { Add-Log "Npcap installed" } else { Add-Log "Npcap not installed - built-in capture is used (optional)" "Yellow" } }
    } catch { Add-Log "Npcap step skipped: $_" "Yellow" }

    # STEP 6: pywin32 post-install
    Set-Prog 65 "Running pywin32 post-install..."
    try {
        $pyDir   = Split-Path $py -Parent
        $pi      = Join-Path $pyDir "pywin32_postinstall.py"
        if (-not (Test-Path $pi)) {
            $pi = Join-Path (Split-Path $pyDir -Parent) "Scripts\pywin32_postinstall.py"
        }
        if (Test-Path $pi) {
            & $py $pi -install 2>&1 | Out-Null
            Add-Log "pywin32 post-install ran"
        } else {
            Add-Log "pywin32_postinstall.py not found -- skipping" "Yellow"
        }
    } catch { Add-Log "pywin32 post-install warning: $_" "Yellow" }

    # STEP 7: Register service
    Set-Prog 76 "Registering Windows Service..."
    try {
        $svcScript = Join-Path $ip "install_service.py"
        if (Test-Path $svcScript) {
            $existing = Get-Service -Name $script:Config.ServiceName -ErrorAction SilentlyContinue
            if ($existing) {
                if ($existing.Status -ne "Stopped") {
                    Stop-Service $script:Config.ServiceName -Force -ErrorAction SilentlyContinue
                    Start-Sleep 2
                }
                Set-Location $ip
                & $py $svcScript remove 2>&1 | Out-Null
                Start-Sleep 2
                Add-Log "Old service removed"
            }
            Set-Location $ip
            & $py $svcScript install 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Set-Service -Name $script:Config.ServiceName -StartupType Automatic -ErrorAction SilentlyContinue
                Add-Log "Service '$($script:Config.ServiceName)' registered (Automatic startup)"
            } else {
                Add-Log "Service registration failed (exit $LASTEXITCODE)" "Yellow"
            }
        } else {
            Add-Log "install_service.py not in $ip -- skipping" "Yellow"
        }
    } catch { Add-Log "Service registration error: $_" "Yellow" }

    # STEP 8: Firewall
    if ($script:Config.Firewall) {
        Set-Prog 84 "Adding firewall rule..."
        try {
            $ruleName = "Net-monit V12.4 Port $($script:Config.Port)"
            netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=TCP localport=$($script:Config.Port) 2>&1 | Out-Null
            Add-Log "Firewall rule added for TCP $($script:Config.Port)"
        } catch { Add-Log "Firewall warning: $_" "Yellow" }
    }

    # STEP 9: Start service
    if ($script:Config.AutoStart) {
        Set-Prog 90 "Starting service..."
        try {
            $svcScript = Join-Path $ip "install_service.py"
            if (Test-Path $svcScript) {
                Set-Location $ip
                & $py $svcScript start 2>&1 | Out-Null
                Start-Sleep 7
                # V12.0 patch 01: Windows reserves some ports (Hyper-V/WSL/Docker). The service then picks the next free one and records it.
                $apFile = Join-Path $ip "data\active_port.txt"
                if (Test-Path $apFile) {
                    $apNum = 0
                    if ([int]::TryParse(((Get-Content $apFile -Raw) -replace "\s",""), [ref]$apNum) -and $apNum -gt 0 -and $apNum -ne $script:Config.Port) {
                        Add-Log ("Port " + $script:Config.Port + " is reserved by Windows or in use. Net-monit uses port " + $apNum + " instead.") "Yellow"
                        try { netsh advfirewall firewall add rule name=("Net-monit port " + $apNum) dir=in action=allow protocol=TCP localport=$apNum 2>&1 | Out-Null } catch {}
                        $script:Config.Port = $apNum
                    }
                }
                $svc = Get-Service -Name $script:Config.ServiceName -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq "Running") {
                    Add-Log "Service running -- http://localhost:$($script:Config.Port)"
                } else {
                    Add-Log ("The service did not stay running. The reason is in " + $ip + "\logs\service.log (see Setup Guide, Troubleshooting).") "Red"
                }
            }
        } catch { Add-Log "Service start warning: $_" "Yellow" }
    }

    # STEP 10: Desktop shortcut
    if ($script:Config.Desktop) {
        Set-Prog 94 "Creating desktop shortcut..."
        try {
            $wsh     = New-Object -ComObject WScript.Shell
            $desktop = [Environment]::GetFolderPath("Desktop")
            $lnk     = $wsh.CreateShortcut((Join-Path $desktop "Net-monit Dashboard.lnk"))
            $lnk.TargetPath  = "http://localhost:$($script:Config.Port)"
            $lnk.Description = "Open Net-monit V12.4 Dashboard"
            $lnk.Save()
            Add-Log "Desktop shortcut created"
        } catch { Add-Log "Shortcut warning: $_" "Yellow" }
    }

    # STEP 11: Registry
    Set-Prog 98 "Writing registry entries..."
    try {
        $rp = "HKLM:\SOFTWARE\NetMonit-V12.4"
        if (-not (Test-Path $rp)) { New-Item -Path $rp -Force | Out-Null }
        Set-ItemProperty -Path $rp -Name "InstallPath"  -Value $ip
        Set-ItemProperty -Path $rp -Name "Version"      -Value $script:Config.AppVersion
        Set-ItemProperty -Path $rp -Name "Port"         -Value $script:Config.Port
        Set-ItemProperty -Path $rp -Name "ServiceName"  -Value $script:Config.ServiceName
        Set-ItemProperty -Path $rp -Name "PythonExe"    -Value $py
        Set-ItemProperty -Path $rp -Name "InstallDate"  -Value (Get-Date -Format "yyyy-MM-dd")
        Add-Log "Registry entries written"
    } catch { Add-Log "Registry warning (non-fatal): $_" "Yellow" }

    Set-Prog 100 "Installation complete."
    Add-Log "======================================================"
    Add-Log "Net-monit V12.4 installation finished successfully."
    Add-Log "======================================================"

    $btnNext.Enabled = $true
    Set-Next { Show-Finish }
}

# ============================================================
# PAGE 6 - FINISH
# ============================================================
function Show-Finish {
    $script:Page = 6
    Clear-Page
    Set-Step 6
    $btnBack.Enabled = $false
    $btnNext.Text    = "Finish"

    $hdr = New-H1 "Installation Complete"
    $hdr.ForeColor = [Drawing.Color]::FromArgb(50,205,90)
    $pnlContent.Controls.Add($hdr)

    $lines = @(
        "Net-monit V12.4 has been installed successfully.",
        "",
        "  Install path : $($script:Config.InstallPath)",
        "  Dashboard    : http://localhost:$($script:Config.Port)",
        "  Service name : $($script:Config.ServiceName)",
        "  Python       : $($script:Config.PythonVersion)",
        "",
        "First-run admin token (one-time, randomly generated per install):",
        "  Email : admin@email.com",
        "  Token : see $($script:Config.InstallPath)\data\FIRST-RUN-ADMIN-TOKEN.txt",
        "",
        "Getting started:",
        "  1. Open http://localhost:$($script:Config.Port) in your browser.",
        "  2. Sign in with the email and token above.",
        "  3. Go to Admin Panel > Users and change the admin token.",
        "  4. Go to Settings > License to activate your license key.",
        "  5. Go to Devices to add network devices to monitor.",
        "",
        "For a free license key, share your Device ID and Activation Code",
        "(from Settings > License) with: abuabdullah.be@outlook.com"
    )
    $pnlContent.Controls.Add((New-Body ($lines -join "`r`n") 74 380))

    $chkOpen = New-ChkBox "Open Net-monit dashboard in browser now" 28 460 $true
    $pnlContent.Controls.Add($chkOpen)

    Set-Next {
        if ($chkOpen.Checked) {
            try { Start-Process "http://localhost:$($script:Config.Port)" } catch {}
        }
        $form.Close()
    }

    Set-Back $null
}

# ============================================================
# MAIN FORM
# ============================================================
$form = New-Object Windows.Forms.Form
$form.Text            = "Net-monit V12.4 Setup Wizard"
$form.Size            = New-Object Drawing.Size(940, 620)
$form.MinimumSize     = New-Object Drawing.Size(940, 620)
$form.StartPosition   = "CenterScreen"
$form.BackColor       = [Drawing.Color]::FromArgb(18,18,24)
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox     = $false
$form.AutoSize        = $false

# -- SIDEBAR -------------------------------------------------
$pnlSide = New-Object Windows.Forms.Panel
$pnlSide.Width     = 186
$pnlSide.Dock      = "Left"
$pnlSide.BackColor = [Drawing.Color]::FromArgb(14,14,20)
$form.Controls.Add($pnlSide)

$lblLogo = New-Object Windows.Forms.Label
$lblLogo.Text      = "Net-monit"
$lblLogo.Font      = New-Object Drawing.Font("Segoe UI", 14, [Drawing.FontStyle]::Bold)
$lblLogo.ForeColor = [Drawing.Color]::White
$lblLogo.AutoSize  = $true
$lblLogo.Location  = New-Object Drawing.Point(16, 20)
$pnlSide.Controls.Add($lblLogo)

$lblVer = New-Object Windows.Forms.Label
$lblVer.Text      = "V12.4 Setup Wizard"
$lblVer.Font      = New-Object Drawing.Font("Segoe UI", 8)
$lblVer.ForeColor = [Drawing.Color]::FromArgb(90,90,110)
$lblVer.AutoSize  = $true
$lblVer.Location  = New-Object Drawing.Point(16, 48)
$pnlSide.Controls.Add($lblVer)

$divSide = New-Object Windows.Forms.Panel
$divSide.BackColor = [Drawing.Color]::FromArgb(40,40,55)
$divSide.Size      = New-Object Drawing.Size(186, 1)
$divSide.Location  = New-Object Drawing.Point(0, 68)
$pnlSide.Controls.Add($divSide)

$script:stepLbls = @()
for ($i = 0; $i -lt $STEPS.Count; $i++) {
    $sl = New-Object Windows.Forms.Label
    $sl.Text      = $STEPS[$i]
    $sl.Font      = New-Object Drawing.Font("Segoe UI", 9)
    $sl.ForeColor = [Drawing.Color]::FromArgb(110,110,130)
    $sl.BackColor = [Drawing.Color]::FromArgb(14,14,20)
    $sl.AutoSize  = $false
    $sl.Size      = New-Object Drawing.Size(186, 38)
    $sl.Location  = New-Object Drawing.Point(0, (76 + $i * 42))
    $sl.Padding   = New-Object Windows.Forms.Padding(16, 0, 0, 0)
    $sl.TextAlign = "MiddleLeft"
    $pnlSide.Controls.Add($sl)
    $script:stepLbls += $sl
}

$lblCopySide = New-Object Windows.Forms.Label
$lblCopySide.Text      = "(c) 2024-2026 Abdullah"
$lblCopySide.Font      = New-Object Drawing.Font("Segoe UI", 7)
$lblCopySide.ForeColor = [Drawing.Color]::FromArgb(55,55,70)
$lblCopySide.AutoSize  = $true
$lblCopySide.Location  = New-Object Drawing.Point(10, 560)
$pnlSide.Controls.Add($lblCopySide)

# -- RIGHT PANEL ---------------------------------------------
$pnlRight = New-Object Windows.Forms.Panel
$pnlRight.Dock      = "Fill"
$pnlRight.BackColor = [Drawing.Color]::FromArgb(18,18,24)
$form.Controls.Add($pnlRight)

# Footer
$pnlFooter = New-Object Windows.Forms.Panel
$pnlFooter.Height    = 58
$pnlFooter.Dock      = "Bottom"
$pnlFooter.BackColor = [Drawing.Color]::FromArgb(12,12,18)
$pnlRight.Controls.Add($pnlFooter)

$footerDiv = New-Object Windows.Forms.Panel
$footerDiv.Height    = 1
$footerDiv.Dock      = "Bottom"
$footerDiv.BackColor = [Drawing.Color]::FromArgb(40,40,55)
$pnlRight.Controls.Add($footerDiv)

$pnlContent = New-Object Windows.Forms.Panel
$pnlContent.Dock       = "Fill"
$pnlContent.BackColor  = [Drawing.Color]::FromArgb(18,18,24)
$pnlContent.AutoScroll = $true
$pnlRight.Controls.Add($pnlContent)

# Buttons
$btnBack = New-Object Windows.Forms.Button
$btnBack.Text      = "< Back"
$btnBack.Size      = New-Object Drawing.Size(100, 36)
$btnBack.Location  = New-Object Drawing.Point(14, 11)
$btnBack.FlatStyle = "Flat"
$btnBack.BackColor = [Drawing.Color]::FromArgb(38,38,52)
$btnBack.ForeColor = [Drawing.Color]::White
$btnBack.Font      = New-Object Drawing.Font("Segoe UI", 9)
$btnBack.FlatAppearance.BorderColor = [Drawing.Color]::FromArgb(60,60,80)
$btnBack.Cursor    = [Windows.Forms.Cursors]::Hand
$pnlFooter.Controls.Add($btnBack)

$btnCancel = New-Object Windows.Forms.Button
$btnCancel.Text      = "Cancel"
$btnCancel.Size      = New-Object Drawing.Size(90, 36)
$btnCancel.Location  = New-Object Drawing.Point(122, 11)
$btnCancel.FlatStyle = "Flat"
$btnCancel.BackColor = [Drawing.Color]::FromArgb(38,38,52)
$btnCancel.ForeColor = [Drawing.Color]::FromArgb(160,160,180)
$btnCancel.Font      = New-Object Drawing.Font("Segoe UI", 9)
$btnCancel.FlatAppearance.BorderColor = [Drawing.Color]::FromArgb(60,60,80)
$btnCancel.Cursor    = [Windows.Forms.Cursors]::Hand
$btnCancel.Add_Click({
    if ($script:Page -eq 5) { return }
    $r = [Windows.Forms.MessageBox]::Show("Cancel installation?","Net-monit Setup","YesNo","Question")
    if ($r -eq "Yes") { $form.Close() }
})
$pnlFooter.Controls.Add($btnCancel)

$btnNext = New-Object Windows.Forms.Button
$btnNext.Text      = "Next >"
$btnNext.Size      = New-Object Drawing.Size(116, 36)
$btnNext.FlatStyle = "Flat"
$btnNext.BackColor = [Drawing.Color]::FromArgb(0,120,215)
$btnNext.ForeColor = [Drawing.Color]::White
$btnNext.Font      = New-Object Drawing.Font("Segoe UI", 9, [Drawing.FontStyle]::Bold)
$btnNext.FlatAppearance.BorderColor = [Drawing.Color]::FromArgb(0,100,185)
$btnNext.Cursor    = [Windows.Forms.Cursors]::Hand
$pnlFooter.Controls.Add($btnNext)

function Reposition-Buttons {
    $btnNext.Location = New-Object Drawing.Point(($pnlFooter.ClientSize.Width - 130), 11)
}
Reposition-Buttons
$pnlFooter.Add_Resize({ Reposition-Buttons })

# -- START ---------------------------------------------------
$form.Add_Shown({
    Reposition-Buttons
    Show-Welcome
    $form.Activate()
})

Write-Host "[INFO] Net-monit V12.4 Setup Wizard starting"
[Windows.Forms.Application]::Run($form)
