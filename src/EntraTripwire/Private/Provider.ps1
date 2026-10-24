<#
.SYNOPSIS
    Discovers whether the paid capabilities are present, and dispatches to them.

.DESCRIPTION
    This file is not a licence check. There is nothing here to disable, because the three
    paid capabilities -- executing a containment plan, delivering a trip to a SOAR
    endpoint, and keeping state apart per tenant profile -- are not in this repository at
    all. They live in a separate module, EntraTripwirePro, and holding that module is the
    entitlement.

    The distinction matters to anyone reading this code with a view to removing a gate.
    There is no gate: these functions ask whether a capability is installed, and when it
    is not they say which one is missing and what the free module does instead. Deleting
    the question does not reveal working code underneath.

    What stays on this side of the line, deliberately:

      * Every verdict. Detection, scoring, suppression and the containment plan are
        computed here, so no paid code can change what this module reports.
      * The write allowlist. The paid module issues its writes through the gateway in this
        repository, injected as a script block, so it cannot make a call this module does
        not permit.
      * The confirmation prompt and the audit log.
#>

$script:TripwireProviderModule = 'EntraTripwirePro'

<#
.SYNOPSIS
    The paid module's state, resolved once per session.
#>
function Get-TripwireProvider {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([switch] $Refresh)

    if (-not $Refresh -and $null -ne $script:TripwireProvider) { return $script:TripwireProvider }

    $absent = {
        param($reason)
        [pscustomobject]@{ Available = $false; Name = $script:TripwireProviderModule; Version = $null; Capabilities = @(); Reason = $reason }
    }

    $available = Get-Module -ListAvailable -Name $script:TripwireProviderModule -ErrorAction SilentlyContinue
    if (-not $available) {
        $script:TripwireProvider = & $absent "$script:TripwireProviderModule is not installed. The free module does everything that produces a verdict; see docs/PRO.md for what the paid module adds and how to get it."
        return $script:TripwireProvider
    }

    try { Import-Module -Name $script:TripwireProviderModule -ErrorAction Stop }
    catch {
        $script:TripwireProvider = & $absent "$script:TripwireProviderModule is installed but did not load: $($_.Exception.Message)"
        return $script:TripwireProvider
    }

    # The contract is one command. A module that does not export it is not a provider this
    # version knows how to talk to, and saying so beats calling into it and failing later.
    if (-not (Get-Command -Name 'Get-EntraTripwireProCapability' -Module $script:TripwireProviderModule -ErrorAction SilentlyContinue)) {
        $script:TripwireProvider = & $absent "$script:TripwireProviderModule loaded but does not export Get-EntraTripwireProCapability, so its capabilities cannot be established. Update it."
        return $script:TripwireProvider
    }

    try { $caps = @(Get-EntraTripwireProCapability) }
    catch {
        $script:TripwireProvider = & $absent "$script:TripwireProviderModule could not report its capabilities: $($_.Exception.Message)"
        return $script:TripwireProvider
    }

    $loaded = Get-Module -Name $script:TripwireProviderModule | Select-Object -First 1
    $script:TripwireProvider = [pscustomobject]@{
        Available    = ($caps.Count -gt 0)
        Name         = $script:TripwireProviderModule
        Version      = if ($loaded) { $loaded.Version } else { $null }
        Capabilities = $caps
        Reason       = if ($caps.Count -gt 0) { $null } else { "$script:TripwireProviderModule is installed but reports no capabilities. Run Get-EntraTripwireProCapability -Verbose for the reason it gives." }
    }
    return $script:TripwireProvider
}

<#
.SYNOPSIS
    Is a named paid capability installed?
.DESCRIPTION
    Never throws. This is consulted while deciding whether containment may act, and an
    exception there would surface during an incident as a crash rather than as an answer.
#>
function Test-TripwireProFeature {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [ValidateSet('containment', 'soar', 'multitenant')] [string] $Feature)

    try { return (@((Get-TripwireProvider).Capabilities) -contains $Feature) }
    catch { return $false }
}

<#
.SYNOPSIS
    Call a paid capability, or fail with the reason it is unavailable.
#>
function Invoke-TripwireProCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('Containment', 'Webhook', 'Profile', 'Activate')] [string] $Capability,
        [Parameter(Mandatory)] [hashtable] $Arguments
    )

    $command = switch ($Capability) {
        'Containment' { 'Invoke-EntraTripwireProContainment' }
        'Webhook' { 'Send-EntraTripwireProWebhook' }
        'Profile' { 'Resolve-EntraTripwireProProfile' }
        'Activate' { 'Enable-EntraTripwireProLicense' }
    }

    $provider = Get-TripwireProvider
    # Activate is the exception: a provider that reports no capabilities because its
    # licence lapsed is exactly the one that needs a new key, so refusing to reach it
    # would make the problem unfixable from here.
    if (-not $provider.Available -and $Capability -ne 'Activate') { throw $provider.Reason }
    if ($Capability -eq 'Activate' -and -not (Get-Module -ListAvailable -Name $script:TripwireProviderModule -ErrorAction SilentlyContinue)) {
        throw $provider.Reason
    }

    $resolved = Get-Command -Name $command -Module $script:TripwireProviderModule -ErrorAction SilentlyContinue
    if (-not $resolved) {
        throw "$($provider.Name) $($provider.Version) does not export $command, so the $Capability capability cannot be used. Update it."
    }

    return (& $resolved @Arguments)
}
