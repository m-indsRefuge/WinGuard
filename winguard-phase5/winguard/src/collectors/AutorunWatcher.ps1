# Phase 5: autorun/persistence watcher. Same lesson as the NetworkExposure
# fix - default severity is "info" for everything, only elevated for
# genuinely suspicious characteristics. On first run, most of what's here
# is legitimate installed software (OneDrive, printer utilities, game
# launchers) - flagging all of it as a concern would just retrain you to
# ignore the tool. What actually matters is (a) anything suspicious-looking
# regardless of when it appeared, and (b) anything NEW appearing after
# baseline - the diff engine's ADDED/REMOVED already surfaces (b) on its
# own without this collector needing to know about it.
#
# Scheduled tasks are filtered to exclude Microsoft's own \Microsoft\Windows\
# namespace - that's hundreds of legitimate built-in tasks that would
# otherwise dominate the baseline for zero signal. Services are filtered to
# auto-start services whose executable lives outside System32/SysWOW64 -
# a reasonable proxy for "third-party" vs "built into Windows."

function Test-SuspiciousCommand {
    param([string]$Command)
    if (-not $Command) { return $false }

    $patterns = @(
        '\\Temp\\'
        '\\AppData\\Local\\Temp\\'
        '-enc(odedcommand)?\s'
        'mshta\.exe'
        '(regsvr32|rundll32|wscript|cscript)[^\r\n]*https?://'
    )
    foreach ($p in $patterns) {
        if ($Command -match $p) { return $true }
    }
    return $false
}

function Get-AutorunFindings {
    $findings = @()

    # --- Registry Run / RunOnce keys ---
    $runKeys = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Label = "HKLM.Run" }
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Label = "HKLM.RunOnce" }
        @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Label = "HKLM.Run32" }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Label = "HKCU.Run" }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Label = "HKCU.RunOnce" }
    )
    foreach ($key in $runKeys) {
        try {
            if (Test-Path $key.Path) {
                $props = Get-ItemProperty -Path $key.Path -ErrorAction Stop
                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Name -like "PS*") { continue }  # skip PSPath, PSParentPath, PSChildName, etc.
                    $isSuspicious = Test-SuspiciousCommand -Command $prop.Value
                    $findings += [PSCustomObject]@{
                        Id       = "Autorun.Registry.$($key.Label).$($prop.Name)"
                        Value    = $prop.Value
                        Severity = $(if ($isSuspicious) { "critical" } else { "info" })
                    }
                }
            }
        }
        catch {
            $findings += [PSCustomObject]@{ Id = "Autorun.Registry.$($key.Label).CheckFailed"; Value = $_.Exception.Message; Severity = "info" }
        }
    }

    # --- Startup folder items (Common - all users, and current User) ---
    $startupFolders = @(
        @{ Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"; Label = "Common" }
        @{ Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\StartUp"; Label = "User" }
    )
    foreach ($folder in $startupFolders) {
        try {
            if (Test-Path $folder.Path) {
                $items = Get-ChildItem -Path $folder.Path -File -ErrorAction Stop
                foreach ($item in $items) {
                    $isSuspicious = Test-SuspiciousCommand -Command $item.FullName
                    $findings += [PSCustomObject]@{
                        Id       = "Autorun.StartupFolder.$($folder.Label).$($item.Name)"
                        Value    = $item.FullName
                        Severity = $(if ($isSuspicious) { "critical" } else { "info" })
                    }
                }
            }
        }
        catch {
            $findings += [PSCustomObject]@{ Id = "Autorun.StartupFolder.$($folder.Label).CheckFailed"; Value = $_.Exception.Message; Severity = "info" }
        }
    }

    # --- Scheduled tasks, excluding Microsoft's own built-in namespace ---
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.TaskPath -notlike "\Microsoft\Windows\*" -and $_.State -ne "Disabled" }

        foreach ($task in $tasks) {
            $actionCommand = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
            $isSuspicious = Test-SuspiciousCommand -Command $actionCommand
            $findings += [PSCustomObject]@{
                Id       = "Autorun.ScheduledTask.$($task.TaskPath)$($task.TaskName)"
                Value    = $actionCommand
                Severity = $(if ($isSuspicious) { "critical" } else { "info" })
            }
        }
    }
    catch {
        $findings += [PSCustomObject]@{ Id = "Autorun.ScheduledTaskCheckFailed"; Value = $_.Exception.Message; Severity = "info" }
    }

    # --- Auto-start services outside System32/SysWOW64 (third-party proxy) ---
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.StartMode -eq "Auto" -and $_.PathName -and
            ($_.PathName -notmatch [regex]::Escape("$env:SystemRoot\System32")) -and
            ($_.PathName -notmatch [regex]::Escape("$env:SystemRoot\SysWOW64"))
        }

        foreach ($svc in $services) {
            $isSuspicious = Test-SuspiciousCommand -Command $svc.PathName
            $findings += [PSCustomObject]@{
                Id       = "Autorun.Service.$($svc.Name)"
                Value    = $svc.PathName
                Severity = $(if ($isSuspicious) { "critical" } else { "info" })
            }
        }
    }
    catch {
        $findings += [PSCustomObject]@{ Id = "Autorun.ServiceCheckFailed"; Value = $_.Exception.Message; Severity = "info" }
    }

    $findings += [PSCustomObject]@{ Id = "Autorun.TotalCount"; Value = $findings.Count.ToString(); Severity = "info" }

    return $findings
}
