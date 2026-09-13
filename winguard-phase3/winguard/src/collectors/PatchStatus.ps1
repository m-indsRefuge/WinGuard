# Phase 3: patch status. The slowest and most fragile check in the whole
# agent is the Windows Update search below - it's a live query against
# the Windows Update Agent API and can take anywhere from a few seconds
# to over a minute, occasionally longer on a machine that hasn't synced
# recently. That's why the scheduled task's execution time limit is set
# generously (10 minutes) in install.ps1 - this is the check most likely
# to need that headroom.

function Test-PendingReboot {
    $indicators = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    )
    foreach ($path in $indicators) {
        if (Test-Path $path) { return $true }
    }
    try {
        $pfro = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
            -Name "PendingFileRenameOperations" -ErrorAction Stop
        if ($pfro) { return $true }
    }
    catch { }
    return $false
}

function Get-PatchStatusFindings {
    param(
        [string]$OllamaEndpoint = "http://localhost:11434",
        [string]$OllamaModel = "phi4-mini:3.8b-q4_K_M"
    )

    $findings = @()

    # --- Pending reboot ---
    $pendingReboot = Test-PendingReboot
    $findings += [PSCustomObject]@{
        Id = "Patch.RebootPending"; Value = $pendingReboot.ToString()
        Severity = $(if ($pendingReboot) { "warning" } else { "info" })
    }

    # --- Days since the last hotfix actually installed ---
    try {
        $lastPatch = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($lastPatch -and $lastPatch.InstalledOn) {
            $daysSince = [math]::Round(((Get-Date) - $lastPatch.InstalledOn).TotalDays)
            $findings += [PSCustomObject]@{
                Id = "Patch.DaysSinceLastInstall"; Value = $daysSince.ToString()
                Severity = $(if ($daysSince -gt 35) { "warning" } else { "info" })
            }
        }
    }
    catch {
        $findings += [PSCustomObject]@{ Id = "Patch.HotfixCheckFailed"; Value = $_.Exception.Message; Severity = "info" }
    }

    # --- Live pending updates via the Windows Update Agent COM API ---
    # Built into Windows - no external module (PSWindowsUpdate etc.)
    # needed, which matters for "easy to install."
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

        $cache = Get-ClassificationCache
        $currentIds = @()
        $count = 0

        foreach ($update in $result.Updates) {
            if ($count -ge 15) { break }  # a fresh install can have dozens pending - cap the noise
            $count++
            $updateId = $update.Identity.UpdateID
            $currentIds += $updateId

            if ($cache.ContainsKey($updateId)) {
                $severity = $cache[$updateId].Severity
            }
            else {
                $urgency = Get-PatchUrgency -Title $update.Title -Endpoint $OllamaEndpoint -Model $OllamaModel
                $severity = $urgency.Severity
                $cache[$updateId] = @{ Severity = $severity; Reason = $urgency.Reason; Title = $update.Title }
            }

            $findings += [PSCustomObject]@{ Id = "Patch.Pending.$updateId"; Value = $update.Title; Severity = $severity }
        }

        # Prune classifications for updates no longer pending (installed
        # or superseded) so the cache doesn't grow forever.
        $prunedCache = @{}
        foreach ($id in $currentIds) { $prunedCache[$id] = $cache[$id] }
        Save-ClassificationCache -Cache $prunedCache

        $findings += [PSCustomObject]@{
            Id = "Patch.PendingCount"; Value = $currentIds.Count.ToString()
            Severity = $(if ($currentIds.Count -gt 0) { "warning" } else { "info" })
        }
    }
    catch {
        $findings += [PSCustomObject]@{ Id = "Patch.UpdateSearchFailed"; Value = $_.Exception.Message; Severity = "info" }
    }

    return $findings
}
