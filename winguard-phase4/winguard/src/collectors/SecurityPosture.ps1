# Phase 2: security posture. Every check is read-only (Get-* only, never
# Set-*) - this collector reports and lets the diff engine flag changes,
# it never touches a setting itself. Severity is assigned deterministically
# right here, not by an LLM - these are known good/bad states, not
# judgment calls that need language understanding.
#
# Each check is wrapped in its own try/catch so one missing feature
# (BitLocker isn't available on Windows Home, for instance) can't take
# down the whole collector - it just becomes a "CheckFailed" finding.

function Get-SecurityPostureFindings {
    $findings = @()

    # --- Windows Defender ---
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $findings += [PSCustomObject]@{
            Id = "Defender.RealTimeProtection"; Value = $mp.RealTimeProtectionEnabled.ToString()
            Severity = $(if ($mp.RealTimeProtectionEnabled) { "info" } else { "critical" })
        }
        $findings += [PSCustomObject]@{
            Id = "Defender.AntivirusEnabled"; Value = $mp.AntivirusEnabled.ToString()
            Severity = $(if ($mp.AntivirusEnabled) { "info" } else { "critical" })
        }
        $findings += [PSCustomObject]@{
            Id = "Defender.BehaviorMonitor"; Value = $mp.BehaviorMonitorEnabled.ToString()
            Severity = $(if ($mp.BehaviorMonitorEnabled) { "info" } else { "warning" })
        }
        $findings += [PSCustomObject]@{
            Id = "Defender.SignatureAgeDays"; Value = $mp.AntivirusSignatureAge.ToString()
            Severity = $(if ($mp.AntivirusSignatureAge -gt 7) { "warning" } else { "info" })
        }
    }
    catch {
        $findings += [PSCustomObject]@{ Id = "Defender.CheckFailed"; Value = $_.Exception.Message; Severity = "warning" }
    }

    # --- Firewall profiles (Domain, Private, Public) ---
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            $findings += [PSCustomObject]@{
                Id = "Firewall.$($p.Name)Enabled"; Value = $p.Enabled.ToString()
                Severity = $(if ($p.Enabled) { "info" } else { "critical" })
            }
        }
    }
    catch {
        $findings += [PSCustomObject]@{ Id = "Firewall.CheckFailed"; Value = $_.Exception.Message; Severity = "warning" }
    }

    # --- BitLocker (system drive only - most people don't care about others) ---
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        foreach ($v in $volumes) {
            if ($v.MountPoint -eq $env:SystemDrive) {
                $findings += [PSCustomObject]@{
                    Id = "BitLocker.SystemDriveProtection"; Value = $v.ProtectionStatus.ToString()
                    Severity = $(if ($v.ProtectionStatus -eq "On") { "info" } else { "warning" })
                }
            }
        }
    }
    catch {
        # Not available on Windows Home, or BitLocker module missing entirely - not itself
        # a finding worth alarming over, just worth knowing the check didn't run.
        $findings += [PSCustomObject]@{ Id = "BitLocker.CheckFailed"; Value = "unavailable on this edition or errored: $($_.Exception.Message)"; Severity = "info" }
    }

    # --- Guest account ---
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
        $findings += [PSCustomObject]@{
            Id = "Account.GuestEnabled"; Value = $guest.Enabled.ToString()
            Severity = $(if ($guest.Enabled) { "critical" } else { "info" })
        }
    }
    catch {
        $findings += [PSCustomObject]@{ Id = "Account.GuestCheckFailed"; Value = $_.Exception.Message; Severity = "info" }
    }

    # --- Local administrators group membership ---
    # Encoded as one sorted, comma-joined string - the diff engine flags
    # ANY membership change as "Changed" on this one Id without needing
    # per-member tracking, which is enough to notice "someone got added."
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop |
            Sort-Object Name | ForEach-Object { $_.Name }
        $findings += [PSCustomObject]@{
            Id = "Account.LocalAdmins"; Value = ($admins -join ", "); Severity = "info"
        }
    }
    catch {
        $findings += [PSCustomObject]@{ Id = "Account.LocalAdminsCheckFailed"; Value = $_.Exception.Message; Severity = "warning" }
    }

    # --- RDP + Network Level Authentication ---
    try {
        $rdpDenied = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
            -Name "fDenyTSConnections" -ErrorAction Stop
        $rdpEnabled = ($rdpDenied -eq 0)
        $findings += [PSCustomObject]@{
            Id = "RDP.Enabled"; Value = $rdpEnabled.ToString()
            Severity = $(if ($rdpEnabled) { "warning" } else { "info" })
        }

        if ($rdpEnabled) {
            $nla = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
                -Name "UserAuthentication" -ErrorAction Stop
            $nlaEnabled = ($nla -eq 1)
            $findings += [PSCustomObject]@{
                Id = "RDP.NLAEnabled"; Value = $nlaEnabled.ToString()
                # RDP open without NLA is a specifically worse combination than either
                # alone - accepts connections before authenticating the user at all.
                Severity = $(if ($nlaEnabled) { "info" } else { "critical" })
            }
        }
    }
    catch {
        $findings += [PSCustomObject]@{ Id = "RDP.CheckFailed"; Value = $_.Exception.Message; Severity = "info" }
    }

    return $findings
}
