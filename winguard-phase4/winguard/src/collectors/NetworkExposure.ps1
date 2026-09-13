# Phase 4: network exposure. Deliberately scoped to two checks rather
# than a full firewall-rule-to-port cross-reference engine:
#
#   1. What's actually listening beyond localhost - the real "is this
#      reachable at all" signal, independent of firewall specifics.
#   2. Is RDP specifically reachable from any remote address - the single
#      most damaging misconfiguration in this category, worth a precise
#      dedicated check rather than folding into a generic rule scan.
#
# A generic rule-to-port cross-reference (matching every firewall rule's
# port/program filters against every listener) would catch more, but
# Windows' default-deny inbound behavior already blocks most ports
# without an explicit allow rule - the marginal value doesn't justify
# the complexity here. Revisit if the two checks below turn out to miss
# something real during dogfooding.

function Get-NetworkExposureFindings {
    $findings = @()

    $riskyPorts = @{
        21 = "FTP"; 23 = "Telnet"; 135 = "RPC"; 139 = "NetBIOS"; 445 = "SMB"
        1433 = "MSSQL"; 1434 = "MSSQL Browser"; 3306 = "MySQL"; 3389 = "RDP"
        5432 = "PostgreSQL"; 5900 = "VNC"; 5985 = "WinRM HTTP"; 5986 = "WinRM HTTPS"
        6379 = "Redis"; 27017 = "MongoDB"
    }

    # --- Listening TCP ports bound beyond localhost ---
    # Loopback-only listeners (127.0.0.1, ::1) are excluded entirely -
    # those are the "correctly configured" case and reporting them would
    # just be noise. Only listeners reachable from outside the machine
    # (0.0.0.0/:: or a real interface IP) are worth a finding.
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { $_.LocalAddress -notin @("127.0.0.1", "::1") }

        foreach ($listener in $listeners) {
            $port = $listener.LocalPort
            $addr = $listener.LocalAddress

            $procName = "unknown"
            try {
                $procName = (Get-Process -Id $listener.OwningProcess -ErrorAction Stop).ProcessName
            }
            catch { }

            $isRisky = $riskyPorts.ContainsKey([int]$port)
            $isAnyInterface = ($addr -eq "0.0.0.0" -or $addr -eq "::")

            $severity =
                if ($isRisky -and $isAnyInterface) { "critical" }
                elseif ($isRisky -or $isAnyInterface) { "warning" }
                else { "info" }

            $label = if ($isRisky) { " ($($riskyPorts[[int]$port]))" } else { "" }

            # Keyed by port alone, not port+address - two distinct binds
            # of the same port on different interfaces is rare enough for
            # TCP that the simpler Id is worth the (small) edge-case loss.
            $findings += [PSCustomObject]@{
                Id       = "Network.Listening.$port"
                Value    = "$addr`:$port$label - process: $procName"
                Severity = $severity
            }
        }

        $findings += [PSCustomObject]@{
            Id = "Network.NonLoopbackListenerCount"; Value = $listeners.Count.ToString()
            Severity = $(if ($listeners.Count -gt 0) { "warning" } else { "info" })
        }
    }
    catch {
        $findings += [PSCustomObject]@{ Id = "Network.ListenerCheckFailed"; Value = $_.Exception.Message; Severity = "info" }
    }

    # --- Is RDP reachable from any remote address? ---
    try {
        $rdpRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True `
            -Direction Inbound -Action Allow -ErrorAction Stop

        $exposedToAny = $false
        foreach ($rule in $rdpRules) {
            $addrFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
            if ($addrFilter -and ($addrFilter.RemoteAddress -contains "Any" -or $addrFilter.RemoteAddress -contains "*")) {
                $exposedToAny = $true
            }
        }

        $findings += [PSCustomObject]@{
            Id = "Network.RDPOpenToAny"; Value = $exposedToAny.ToString()
            Severity = $(if ($exposedToAny) { "critical" } else { "info" })
        }
    }
    catch {
        $findings += [PSCustomObject]@{ Id = "Network.RDPRuleCheckFailed"; Value = $_.Exception.Message; Severity = "info" }
    }

    return $findings
}
