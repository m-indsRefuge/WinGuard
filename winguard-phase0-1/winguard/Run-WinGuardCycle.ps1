# Phase 0-1 entry point. No real collectors yet - Phases 2-5 add those.
# This proves the plumbing works: elevation actually took effect, the
# snapshot store persists between runs, and the diff engine correctly
# reports "no change" on a stable value and "changed" when something
# (like a reboot) actually moves.
#
# Run this manually first from a normal (non-admin) PowerShell window,
# then again from an elevated one, and compare System.RunningElevated in
# both - that's the fastest way to confirm what the scheduled task will
# actually see once installed.

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here "src\core\Storage.ps1")
. (Join-Path $here "src\core\BaselineDiff.ps1")

function Get-HeartbeatFindings {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $os = Get-CimInstance Win32_OperatingSystem

    return @(
        [PSCustomObject]@{ Id = "System.RunningElevated"; Value = $isElevated.ToString(); Severity = "info" }
        [PSCustomObject]@{ Id = "System.OSVersion"; Value = $os.Version; Severity = "info" }
        [PSCustomObject]@{ Id = "System.LastBoot"; Value = $os.LastBootUpTime.ToString("o"); Severity = "info" }
    )
}

Initialize-WinGuardPaths

$collectorName = "Heartbeat"
$previous = Get-PreviousSnapshot -CollectorName $collectorName
$current = Get-HeartbeatFindings
$diff = Compare-Findings -Previous $previous -Current $current

if (-not $previous) {
    Write-WinGuardLog "First run - no baseline yet. Recorded $($current.Count) findings."
}
elseif ($diff.HasDrift) {
    Write-WinGuardLog "Drift detected: $($diff.Added.Count) added, $($diff.Removed.Count) removed, $($diff.Changed.Count) changed."
    foreach ($c in $diff.Changed) {
        Write-WinGuardLog "  CHANGED $($c.Id): '$($c.OldValue)' -> '$($c.NewValue)'"
    }
}
else {
    Write-WinGuardLog "No change since last run."
}

Save-Snapshot -CollectorName $collectorName -Findings $current
