# Phase 0: registers WinGuard as a scheduled task that runs elevated
# without an interactive UAC prompt each cycle. Run this once from an
# ELEVATED PowerShell window (right-click PowerShell -> Run as
# administrator) - registering a "highest privileges" task itself
# requires admin rights, even though the task will later run unattended.

param(
    [int]$IntervalMinutes = 15  # short interval for testing; widen to 240 (4h) once verified
)

$taskName = "WinGuard"
$scriptPath = Join-Path $PSScriptRoot "Run-WinGuardCycle.ps1"

if (-not (Test-Path $scriptPath)) {
    throw "Can't find Run-WinGuardCycle.ps1 next to install.ps1 - check you're running this from the repo root."
}

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration ([TimeSpan]::MaxValue)

$principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType S4U `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "WinGuard posture monitoring - runs elevated, read-only, every $IntervalMinutes minutes." `
    -Force | Out-Null

Write-Host "Registered scheduled task '$taskName', running every $IntervalMinutes minutes." -ForegroundColor Green
Write-Host "Verify it actually runs elevated with:" -ForegroundColor Yellow
Write-Host "  Start-ScheduledTask -TaskName '$taskName'"
Write-Host "  Get-Content `"$env:ProgramData\WinGuard\logs\activity.log`" -Tail 5"
Write-Host "  Get-Content `"$env:ProgramData\WinGuard\data\Heartbeat.snapshot.json`""
Write-Host "System.RunningElevated should read 'True' - if it reads 'False', the task ran but not elevated." -ForegroundColor Yellow
