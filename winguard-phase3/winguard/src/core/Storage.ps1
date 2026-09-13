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

# --- Classification cache -----------------------------------------------
# Keyed by a stable identifier (Windows Update's own GUID, not the title -
# titles can shift slightly between searches). Avoids re-calling Ollama
# for an update that's still pending from the last cycle - same principle
# as caching a tab's classification in Reaper.

function Get-ClassificationCache {
    $path = Join-Path $script:WinGuardDataPath "classification-cache.json"
    if (-not (Test-Path $path)) { return @{} }
    $raw = Get-Content $path -Raw | ConvertFrom-Json
    $cache = @{}
    if ($raw) {
        foreach ($prop in $raw.PSObject.Properties) { $cache[$prop.Name] = $prop.Value }
    }
    return $cache
}

function Save-ClassificationCache {
    param([Parameter(Mandatory)][hashtable]$Cache)
    Initialize-WinGuardPaths
    $path = Join-Path $script:WinGuardDataPath "classification-cache.json"
    $Cache | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
}

# --- Config ---------------------------------------------------------------
# Plain JSON file, created with defaults on first run if missing. No UI
# yet - hand-edit C:\ProgramData\WinGuard\config.json to change the model
# or point at a different Ollama host.

function Get-WinGuardConfig {
    $defaults = @{
        OllamaEndpoint = "http://localhost:11434"
        OllamaModel    = "phi4-mini:3.8b-q4_K_M"
    }
    $path = Join-Path $env:ProgramData "WinGuard\config.json"
    if (Test-Path $path) {
        $loaded = Get-Content $path -Raw | ConvertFrom-Json
        foreach ($prop in $loaded.PSObject.Properties) { $defaults[$prop.Name] = $prop.Value }
    }
    else {
        Initialize-WinGuardPaths
        $defaults | ConvertTo-Json | Set-Content -Path $path -Encoding UTF8
    }
    return $defaults
}
