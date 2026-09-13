# Orchestrator. Each collector below returns an array of findings
# (Id/Value/Severity) - this loop handles fetching the previous
# snapshot, diffing, logging, and saving identically for all of them, so
# adding Phase 3-5's collectors means adding one line here, not new
# plumbing.

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here "src\core\Storage.ps1")
. (Join-Path $here "src\core\BaselineDiff.ps1")
. (Join-Path $here "src\core\Classifier.ps1")
. (Join-Path $here "src\collectors\SecurityPosture.ps1")
. (Join-Path $here "src\collectors\PatchStatus.ps1")
. (Join-Path $here "src\collectors\NetworkExposure.ps1")

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
$config = Get-WinGuardConfig

$collectors = @(
    @{ Name = "Heartbeat"; Fetch = { Get-HeartbeatFindings } }
    @{ Name = "SecurityPosture"; Fetch = { Get-SecurityPostureFindings } }
    @{ Name = "PatchStatus"; Fetch = { Get-PatchStatusFindings -OllamaEndpoint $config.OllamaEndpoint -OllamaModel $config.OllamaModel } }
    @{ Name = "NetworkExposure"; Fetch = { Get-NetworkExposureFindings } }
)

foreach ($collector in $collectors) {
    $name = $collector.Name
    $previous = Get-PreviousSnapshot -CollectorName $name
    $current = & $collector.Fetch

    $diff = Compare-Findings -Previous $previous -Current $current

    if (-not $previous) {
        Write-WinGuardLog "[$name] First run - no baseline yet. Recorded $($current.Count) findings."
    }
    elseif ($diff.HasDrift) {
        Write-WinGuardLog "[$name] Drift detected: $($diff.Added.Count) added, $($diff.Removed.Count) removed, $($diff.Changed.Count) changed."
        foreach ($a in $diff.Added) {
            Write-WinGuardLog "  [$name] ADDED $($a.Id) = '$($a.Value)' (severity: $($a.Severity))"
        }
        foreach ($c in $diff.Changed) {
            Write-WinGuardLog "  [$name] CHANGED $($c.Id): '$($c.OldValue)' -> '$($c.NewValue)' (severity: $($c.Severity))"
        }
        foreach ($r in $diff.Removed) {
            Write-WinGuardLog "  [$name] REMOVED $($r.Id) (was '$($r.Value)')"
        }
    }
    else {
        Write-WinGuardLog "[$name] No change since last run."
    }

    Save-Snapshot -CollectorName $name -Findings $current
}
