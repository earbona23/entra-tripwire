<#
.SYNOPSIS
    Check everything this module needs before a real run, and say what to do about each gap.

.DESCRIPTION
    The first run of a security tool is where it is judged, and the usual way it is lost is
    a raw exception from the middle of a pipeline: a missing SDK surfacing as "the term
    Connect-MgGraph is not recognized", an empty inventory surfacing as nothing at all.
    This command asks every question up front and answers each one with the command that
    closes the gap.

    It is read-only and it touches no network. Nothing here calls Microsoft Graph -- the
    tenant-side questions it can answer locally (is the SDK installed, is there a session,
    is there a baseline on disk) it answers, and the ones it cannot it does not guess at.

    Each check reports who needs it:

      Any run         true whatever you are doing, including -Demo
      A real tenant   needed the moment you point this at a tenant; -Demo needs none of it
      Pro features    needed only for the capabilities EntraTripwirePro provides

    So a machine that can only run the demo is not told it is broken. It is told which
    checks the demo does not need.

.PARAMETER Path
    Read a specific decoy inventory instead of the profile default.

.EXAMPLE
    Test-TripwireReadiness

.EXAMPLE
    Test-TripwireReadiness | Where-Object Status -eq 'Action required' | Format-List
#>
function Test-TripwireReadiness {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $Path
    )

    $checks = [System.Collections.Generic.List[object]]::new()

    # Blocking separates "a run against a tenant cannot start" from "a run will be worse
    # than it should be". A missing SDK is the first; an empty inventory and a missing
    # baseline are the second, and Start-EntraTripwire offers to fix both as it goes, so
    # calling them blockers would stop the guided run that exists to resolve them.
    function New-Check {
        param(
            [Parameter(Mandatory)] [string] $Check,
            [Parameter(Mandatory)] [ValidateSet('Ready', 'Action required', 'Not installed')] [string] $Status,
            [Parameter(Mandatory)] [ValidateSet('Any run', 'A real tenant', 'Pro features')] [string] $NeededFor,
            [string] $Detail = '',
            [string] $Action = '',
            [switch] $Blocking
        )
        [pscustomobject]@{
            PSTypeName = 'EntraTripwire.ReadinessCheck'
            Check      = $Check
            Status     = $Status
            NeededFor  = $NeededFor
            Blocking   = [bool]$Blocking
            Detail     = $Detail
            Action     = $Action
        }
    }

    # --- PowerShell itself ------------------------------------------------------------
    # Compared member by member rather than against [version]'7.2'. $PSVersionTable.PSVersion
    # is a SemanticVersion on PowerShell 7, and comparing the two types is not something to
    # rely on inside the one check whose job is to tell the operator what they are running.
    $v = $PSVersionTable.PSVersion
    $supported = ($v.Major -gt 7) -or ($v.Major -eq 7 -and $v.Minor -ge 2)
    $checks.Add((New-Check -Check 'PowerShell 7.2 or later' -NeededFor 'Any run' -Blocking `
                -Status $(if ($supported) { 'Ready' } else { 'Action required' }) `
                -Detail "This session is PowerShell $v." `
                -Action $(if ($supported) { '' } else { 'Install PowerShell 7: https://aka.ms/powershell-release' })))

    # --- The Graph SDK, which DEMO mode deliberately does not need --------------------
    $sdk = @(Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' -ErrorAction SilentlyContinue)
    if ($sdk.Count -gt 0) {
        $newest = @($sdk | Sort-Object Version -Descending)[0].Version
        $checks.Add((New-Check -Check 'Microsoft.Graph.Authentication' -Status 'Ready' -NeededFor 'A real tenant' `
                    -Detail "Version $newest is installed."))
    }
    else {
        $checks.Add((New-Check -Check 'Microsoft.Graph.Authentication' -Status 'Action required' -NeededFor 'A real tenant' -Blocking `
                    -Detail 'Not installed. Connecting to a tenant needs it; the demo does not.' `
                    -Action 'Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'))
    }

    # --- A session ---------------------------------------------------------------------
    if ($null -ne $script:TripwireSession) {
        $s = $script:TripwireSession
        $checks.Add((New-Check -Check 'Tenant session' -Status 'Ready' -NeededFor 'A real tenant' `
                    -Detail "Connected to $($s.TenantId) in $($s.Mode) mode as $($s.Account)."))
    }
    else {
        $checks.Add((New-Check -Check 'Tenant session' -Status 'Action required' -NeededFor 'A real tenant' `
                    -Detail 'Not connected. Detect mode asks for two read scopes and nothing else.' `
                    -Action 'Connect-EntraTripwire -TenantId <your-tenant> -Mode Detect'))
    }

    # --- Somewhere to keep the inventory and the baseline ------------------------------
    # Resolved and created the same way the tool itself would on first use, so a config
    # directory that cannot be created is reported here rather than halfway through a run.
    $stateRoot = $null
    try {
        $stateRoot = Split-Path -Parent (Get-TripwireStatePath -Name 'decoys.json')
        $checks.Add((New-Check -Check 'Local state directory' -Status 'Ready' -NeededFor 'A real tenant' `
                    -Detail "$stateRoot (the decoy inventory and the baseline live here, never in the directory)."))
    }
    catch {
        $checks.Add((New-Check -Check 'Local state directory' -Status 'Action required' -NeededFor 'A real tenant' -Blocking `
                    -Detail "Could not be created: $($_.Exception.Message)" `
                    -Action 'Point $env:ENTRATRIPWIRE_CONFIG_DIR at a directory you can write to.'))
    }

    # --- The decoy inventory -----------------------------------------------------------
    # A corrupt inventory throws by design, because an unreadable inventory and an empty
    # one produce the same zero trips downstream. Caught here so the first run reports it
    # as a named gap with a fix rather than as an unhandled exception.
    $decoyCount = 0
    try {
        $decoys = @(if ($Path) { Get-TripwireDecoy -Path $Path } else { Get-TripwireDecoy })
        $decoyCount = $decoys.Count
        if ($decoyCount -gt 0) {
            $orphans = @($decoys | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.objectId) }).Count
            $detail = "$decoyCount decoy(s) recorded."
            if ($orphans -gt 0) { $detail += " $orphans of them have no object id, so they cannot be removed or contained by id." }
            $checks.Add((New-Check -Check 'Decoy inventory' -Status 'Ready' -NeededFor 'A real tenant' -Detail $detail))
        }
        else {
            $checks.Add((New-Check -Check 'Decoy inventory' -Status 'Action required' -NeededFor 'A real tenant' `
                        -Detail 'Empty. With no decoys planted, no touch can ever be detected: a run would be blind, not quiet.' `
                        -Action "New-TripwireDecoy -Type User -DisplayName 'svc-backup-archive' -UserPrincipalName 'svc-backup-archive@<your-domain>'"))
        }
    }
    catch {
        # Blocking: an unreadable state file raises a terminating error on the read path
        # by design, because an unreadable inventory and an empty one both detect nothing
        # and only one of them means "nothing happened".
        $checks.Add((New-Check -Check 'Decoy inventory' -Status 'Action required' -NeededFor 'A real tenant' -Blocking `
                    -Detail "Unreadable: $($_.Exception.Message)" `
                    -Action 'Fix or delete the inventory file named above. An unreadable inventory detects nothing.'))
    }

    # --- The baseline ------------------------------------------------------------------
    try {
        $baseline = Get-TripwireBaseline -WarningAction SilentlyContinue
        if ($null -eq $baseline) {
            $checks.Add((New-Check -Check 'Tenant baseline' -Status 'Action required' -NeededFor 'A real tenant' `
                        -Detail 'None on disk. The origin and off-hours signals will be WITHHELD and every trip marked degraded.' `
                        -Action 'Get-TripwireBaseline -Build -Days 30 -Save'))
        }
        elseif ([int]$baseline.totalSignIns -le 0) {
            $checks.Add((New-Check -Check 'Tenant baseline' -Status 'Action required' -NeededFor 'A real tenant' `
                        -Detail 'Present but built from zero successful sign-ins, which suppresses nothing. Usually a missing AuditLog.Read.All, or a tenant without the licence sign-in log retention needs.' `
                        -Action 'Get-TripwireBaseline -Build -Days 30 -Save'))
        }
        else {
            $age = ''
            $generated = ConvertTo-TripwireUtcOrNull $baseline.generatedAt
            if ($null -ne $generated) {
                $days = [Math]::Round(([DateTime]::UtcNow - $generated).TotalDays, 1)
                $age = " Built $days day(s) ago."
            }
            # A baseline read from disk arrives as a PSCustomObject and one built in memory
            # as a hashtable. Counting the properties of a hashtable would report the count
            # of Keys/Values/Count, which is 3 whatever the tenant looks like.
            $countries = 0
            if ($null -ne $baseline.countries) {
                $countries = if ($baseline.countries -is [System.Collections.IDictionary]) { $baseline.countries.Count }
                else { @($baseline.countries.PSObject.Properties).Count }
            }
            $checks.Add((New-Check -Check 'Tenant baseline' -Status 'Ready' -NeededFor 'A real tenant' `
                        -Detail "$($baseline.totalSignIns) sign-in(s) across $countries country/countries.$age"))
        }
    }
    catch {
        $checks.Add((New-Check -Check 'Tenant baseline' -Status 'Action required' -NeededFor 'A real tenant' -Blocking `
                    -Detail "Unreadable: $($_.Exception.Message)" `
                    -Action 'Fix or delete the baseline file, then run Get-TripwireBaseline -Build -Save.'))
    }

    # --- The paid module, reported as a fact rather than as a gap ----------------------
    $provider = Get-TripwireProvider
    if ($provider.Available) {
        $checks.Add((New-Check -Check 'EntraTripwirePro' -Status 'Ready' -NeededFor 'Pro features' `
                    -Detail "$($provider.Name) $($provider.Version) provides: $(@($provider.Capabilities) -join ', ')."))
    }
    else {
        $checks.Add((New-Check -Check 'EntraTripwirePro' -Status 'Not installed' -NeededFor 'Pro features' `
                    -Detail 'Everything that produces a verdict -- detection, scoring, suppression and the containment plan -- is in this module and needs nothing else.' `
                    -Action 'See docs/PRO.md. Executing a containment plan, JSONL/webhook delivery and per-tenant profiles live there.'))
    }

    return $checks.ToArray()
}

# A table of five columns does not fit a terminal, so the default view is the three that
# answer "what is wrong and what do I type". Detail and NeededFor stay on the object for
# Format-List and for scripts.
Update-TypeData -TypeName 'EntraTripwire.ReadinessCheck' -DefaultDisplayPropertySet 'Check', 'Status', 'Action' -Force
