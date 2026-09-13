# Phase 1: the shared diff engine. Every collector emits an array of
# "findings" - flat objects with an Id, a Value, and a Severity - rather
# than raw OS state, so this diff logic works identically for Defender
# status, patch state, network exposure, or autoruns without knowing
# anything domain-specific about any of them.
#
# Finding shape: @{ Id = "Defender.RealTimeProtection"; Value = "Enabled"; Severity = "info" }

function Compare-Findings {
    param(
        [array]$Previous,
        [array]$Current
    )

    $previousById = @{}
    if ($Previous) {
        foreach ($f in $Previous) { $previousById[$f.Id] = $f }
    }
    $currentById = @{}
    foreach ($f in $Current) { $currentById[$f.Id] = $f }

    $added = @()
    $removed = @()
    $changed = @()

    foreach ($id in $currentById.Keys) {
        if (-not $previousById.ContainsKey($id)) {
            $added += $currentById[$id]
        }
        elseif ($previousById[$id].Value -ne $currentById[$id].Value) {
            $changed += [PSCustomObject]@{
                Id       = $id
                OldValue = $previousById[$id].Value
                NewValue = $currentById[$id].Value
                Severity = $currentById[$id].Severity
            }
        }
    }

    foreach ($id in $previousById.Keys) {
        if (-not $currentById.ContainsKey($id)) {
            $removed += $previousById[$id]
        }
    }

    return [PSCustomObject]@{
        Added   = $added
        Removed = $removed
        Changed = $changed
        HasDrift = ($added.Count -gt 0 -or $removed.Count -gt 0 -or $changed.Count -gt 0)
    }
}
