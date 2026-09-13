# Phase 3: classifies a pending Windows update's urgency. Tries Ollama
# first; any failure (not running, network error, bad response) falls
# back to a keyword heuristic rather than leaving the update unclassified.
# This is a native PowerShell call, not a browser one - no OLLAMA_ORIGINS
# setup needed here, unlike Reaper.

function Invoke-OllamaClassifyUpdate {
    param(
        [Parameter(Mandatory)][string]$Title,
        [string]$Endpoint = "http://localhost:11434",
        [string]$Model = "phi4-mini:3.8b-q4_K_M"
    )

    $prompt = @"
Classify the urgency of installing this pending Windows update. Respond with only JSON in the form {"severity": "critical", "reason": "one short sentence"} - severity must be exactly one of critical, warning, or info.

- critical: the description suggests this patches something already being actively exploited, or is itself flagged a zero-day.
- warning: a routine security or cumulative update - install soon, no evidence of active exploitation.
- info: a feature update, preview, driver, or non-security update - can wait.

Update title: $Title
"@

    $body = @{ model = $Model; prompt = $prompt; stream = $false; format = "json" } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "$Endpoint/api/generate" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 30
    $parsed = $response.response | ConvertFrom-Json

    if ($parsed.severity -notin @("critical", "warning", "info")) {
        throw "Ollama returned an unrecognized severity: $($parsed.severity)"
    }

    return [PSCustomObject]@{ Severity = $parsed.severity; Reason = $parsed.reason }
}

function Get-LocalHeuristicUrgency {
    param([Parameter(Mandatory)][string]$Title)

    # Deliberately never returns "critical" - a keyword match on the title
    # alone can't reliably tell you something is actively exploited, only
    # Ollama reading the fuller description context can make that call.
    if ($Title -match "Preview|Optional|Driver") {
        return [PSCustomObject]@{ Severity = "info"; Reason = "heuristic: preview/optional/driver update" }
    }
    if ($Title -match "Security|Critical|Cumulative") {
        return [PSCustomObject]@{ Severity = "warning"; Reason = "heuristic: security-related update, urgency not confirmed" }
    }
    return [PSCustomObject]@{ Severity = "warning"; Reason = "heuristic: unclassified update, defaulting to warning" }
}

function Get-PatchUrgency {
    param(
        [Parameter(Mandatory)][string]$Title,
        [string]$Endpoint = "http://localhost:11434",
        [string]$Model = "phi4-mini:3.8b-q4_K_M"
    )

    try {
        return Invoke-OllamaClassifyUpdate -Title $Title -Endpoint $Endpoint -Model $Model
    }
    catch {
        Write-WinGuardLog "Ollama classify failed for '$Title': $($_.Exception.Message) - falling back to heuristic."
        return Get-LocalHeuristicUrgency -Title $Title
    }
}
