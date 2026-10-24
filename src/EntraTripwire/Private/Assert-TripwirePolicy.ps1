<#
.SYNOPSIS
    Refuse to score against a policy that is not fully populated.

.DESCRIPTION
    This function exists because of two defects that were measured against this module,
    both of which came from the same place -- Get-TripwirePolicy merges -Override by
    TOP-LEVEL key, so replacing a sub-object with one that is missing a member silently
    leaves that member $null -- and both of which PowerShell then hides:

      * A missing threshold reads as $null, and `50 -ge $null` is $true. A policy whose
        Threshold object lost its High member banded EVERY trip as High, including one
        scoring 34.6, and High is the only band Invoke-TripwireContainment will act on.
        That is a configuration typo turning a detector into "contain everything".

      * A missing weight casts to 0.0 through New-TripwireSignal's [double] parameter.
        The signal still reports Available = $true with its real Raw strength, contributes
        nothing to the total, and the trip is NOT marked degraded. A signal screamed and
        the score said Low.

    The two fail in opposite directions, which is the point: neither can be caught by a
    rule of thumb about erring on the safe side. The only defence is to refuse a policy
    that is not complete, loudly, at the moment it is built or handed in -- and the error
    has to name the member, because the operator who typo'd it is reading the message.

    Throws on anything incomplete. Warns, rather than throws, when the weights do not sum
    to 1.00: a deliberate recalibration is legitimate, but confidence then stops being a
    percentage of obtainable evidence and two deployments' scores stop meaning the same
    thing, so the operator is told.
#>

<#
.SYNOPSIS
    Is this value really a number?
.DESCRIPTION
    [double]$null and [double]'' are both 0, so a bare cast would wave through exactly the
    empty members Assert-TripwirePolicy exists to catch. A bool is excluded on purpose:
    $true casts to 1 and would pass as a threshold.
#>
function Test-TripwireNumber {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Value)

    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $false }
    if ($Value -is [int] -or $Value -is [int64] -or $Value -is [double] -or
        $Value -is [decimal] -or $Value -is [single]) {
        return $true
    }
    if ($Value -is [string]) {
        $parsed = 0.0
        return [double]::TryParse($Value, [ref] $parsed)
    }
    return $false
}

function Assert-TripwirePolicy {
    [CmdletBinding()]
    [OutputType([void])]
    param([Parameter(Mandatory)] [AllowNull()] $Policy)

    if ($null -eq $Policy) {
        throw 'No scoring policy was supplied. Pass one from Get-TripwirePolicy, or omit -Policy to use the default.'
    }

    # Dotted access rather than Get-TripwireMapValue: it reads members off a
    # PSCustomObject and keys off a hashtable alike, returns $null for an absent one, and
    # does it without a cmdlet invocation per member. This function runs on every policy
    # an operator builds, so its own cost has to stay out of the way.
    $problems = [System.Collections.Generic.List[string]]::new()

    foreach ($group in @(
            @{ Name = 'Weights'; Members = @('DecoyPurity', 'OriginAnomaly', 'CrossDecoyFanOut', 'OffHours') }
            @{ Name = 'Threshold'; Members = @('High', 'Medium') }
            @{ Name = 'OriginRaw'; Members = @('UnseenCountry', 'RareCountry', 'UnseenAsn', 'RareAsn') }
        )) {
        $container = $Policy.($group.Name)
        if ($null -eq $container) {
            $problems.Add("Policy.$($group.Name) is missing. It must carry: $($group.Members -join ', ').")
            continue
        }
        foreach ($member in $group.Members) {
            if (-not (Test-TripwireNumber $container.$member)) {
                $problems.Add("Policy.$($group.Name).$member is missing or not a number.")
            }
        }
    }

    foreach ($scalar in @('RareCountryShare', 'RareAsnShare', 'ImpossibleTravelKph',
            'CorrelationWindowMinutes', 'ProvisioningGraceMinutes')) {
        if (-not (Test-TripwireNumber $Policy.$scalar)) {
            $problems.Add("Policy.$scalar is missing or not a number.")
        }
    }

    foreach ($tierSet in @(
            @{ Name = 'PurityTiers'; Bound = 'MaxUses' }
            @{ Name = 'FanOutTiers'; Bound = 'MinDecoys' }
        )) {
        $tiers = @($Policy.($tierSet.Name))
        if ($tiers.Count -eq 0 -or ($tiers.Count -eq 1 -and $null -eq $tiers[0])) {
            # An empty tier set is not a neutral policy: every decoy would fall through to
            # "contaminated" and the whole dominant signal would quietly read zero.
            $problems.Add("Policy.$($tierSet.Name) is empty. With no tiers the signal it drives can never score above zero.")
            continue
        }
        for ($i = 0; $i -lt $tiers.Count; $i++) {
            if (-not (Test-TripwireNumber $tiers[$i].($tierSet.Bound))) {
                $problems.Add("Policy.$($tierSet.Name)[$i].$($tierSet.Bound) is missing or not a number.")
            }
            if (-not (Test-TripwireNumber $tiers[$i].Raw)) {
                $problems.Add("Policy.$($tierSet.Name)[$i].Raw is missing or not a number.")
            }
        }
    }

    if ($problems.Count -gt 0) {
        throw ("This scoring policy is incomplete, so EntraTripwire will not score against it:" +
            [Environment]::NewLine + '  - ' + ($problems -join ([Environment]::NewLine + '  - ')) +
            [Environment]::NewLine +
            'Get-TripwirePolicy -Override replaces whole top-level keys, so a sub-object passed in ' +
            'must carry every member. Start from (Get-TripwirePolicy).Threshold and change what you need.')
    }

    $high = [double]$Policy.Threshold.High
    $medium = [double]$Policy.Threshold.Medium
    if ($high -lt $medium) {
        throw "Policy.Threshold.High ($high) is below Policy.Threshold.Medium ($medium). The High band would be unreachable and containment could never fire."
    }

    $w = $Policy.Weights
    $sum = [double]$w.DecoyPurity + [double]$w.OriginAnomaly + [double]$w.CrossDecoyFanOut + [double]$w.OffHours
    if ([Math]::Abs($sum - 1.0) -gt 0.0001) {
        Write-TripwireLog -Level 'Warn' -Message (
            'The scoring weights sum to {0:N4}, not 1.00. Confidence is no longer a percentage of obtainable evidence, and the published thresholds (High {1}, Medium {2}) no longer mean what docs/scoring.md says they mean.' -f $sum, $high, $medium)
    }
}

<#
.SYNOPSIS
    The one place a -Policy argument becomes a policy the engine will score against.

.DESCRIPTION
    Omitted, it is the default from Get-TripwirePolicy. Supplied, it is validated here --
    a hand-built policy, or one assembled by a caller that never went through
    Get-TripwirePolicy, gets the same refusal an incomplete override does.

    Validation is remembered by object identity so that scoring ten thousand touches
    against one policy validates it once. The cache is a reference comparison, not a deep
    one: a policy MUTATED in place after it was validated will not be re-checked. Building
    a policy and then editing its members is not a supported pattern -- use
    Get-TripwirePolicy -Override, which validates the result.
#>
function Resolve-TripwirePolicy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowNull()] $Policy)

    if (-not $Policy) { return Get-TripwirePolicy }

    if (-not [object]::ReferenceEquals($script:TripwireValidatedPolicy, $Policy)) {
        Assert-TripwirePolicy -Policy $Policy
        $script:TripwireValidatedPolicy = $Policy
    }
    return $Policy
}
