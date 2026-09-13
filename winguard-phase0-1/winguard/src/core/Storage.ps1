# Phase 1: local snapshot storage + rolling history. Every collector
# calls Get-PreviousSnapshot before it runs and Save-Snapshot after, so
# the diff engine always has something to compare against.
#
# Data lives in ProgramData, not the user profile - the scheduled task
# runs elevated, and ProgramData is the conventional place for
# machine-level agent state that isn't tied to one user's roaming profile.

$script:WinGuardDataPath = "$env:ProgramData\WinGuard\data"
$script:WinGuardHistoryPath = "$env:ProgramData\WinGuard\history"
$script:WinGuardLogPath = "$env:ProgramData\WinGuard\logs"

function Initialize-WinGuardPaths {
    foreach ($path in @($script:WinGuardDataPath, $script:WinGuardHistoryPath, $script:WinGuardLogPath)) {
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

function Get-PreviousSnapshot {
    param([Parameter(Mandatory)][string]$CollectorName)

    $path = Join-Path $script:WinGuardDataPath "$CollectorName.snapshot.json"
    if (-not (Test-Path $path)) {
        return $null
    }
    return Get-Content $path -Raw | ConvertFrom-Json
}

function Save-Snapshot {
    param(
        [Parameter(Mandatory)][string]$CollectorName,
        [Parameter(Mandatory)][array]$Findings
    )

    Initialize-WinGuardPaths
    $path = Join-Path $script:WinGuardDataPath "$CollectorName.snapshot.json"
    $Findings | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8

    # Rolling history: one timestamped copy per run, so trend questions
    # ("how many times this month") are answerable later without having
    # thrown the data away.
    $historyFile = Join-Path $script:WinGuardHistoryPath ("{0}_{1:yyyyMMdd_HHmmss}.json" -f $CollectorName, (Get-Date))
    $Findings | ConvertTo-Json -Depth 5 | Set-Content -Path $historyFile -Encoding UTF8
}

function Write-WinGuardLog {
    param([Parameter(Mandatory)][string]$Message)

    Initialize-WinGuardPaths
    $line = "{0:yyyy-MM-dd HH:mm:ss} - {1}" -f (Get-Date), $Message
    Add-Content -Path (Join-Path $script:WinGuardLogPath "activity.log") -Value $line
    Write-Host $line
}
