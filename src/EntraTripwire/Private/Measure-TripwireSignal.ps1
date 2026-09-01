<#
    The four evidence signals, and the suppression rules that run before any of them.

    Design rule for this whole file: a signal that cannot be evaluated returns
    Available = $false and contributes zero. It never returns a neutral-looking 0 that is
    indistinguishable from "evaluated, found nothing". The composed score carries the list
    of withheld signals so a human -- and Invoke-TripwireContainment -- can tell a quiet
    tenant apart from a blind detector.
#>

<#
.SYNOPSIS
    Signal (a): has this decoy ever been used legitimately?

.DESCRIPTION
    A decoy is only evidence to the degree that nothing legitimate touches it. The moment
    a backup job, a licensing script or a curious administrator starts hitting it, every
    subsequent touch is ambiguous -- and this signal is the one that carries the most
    weight, so its decay is what stops a polluted decoy from driving containment.

    LegitimateUseCount is maintained by the operator (Set it on the decoy record when you
    find a legitimate consumer). It is deliberately not inferred from the logs: inferring
    it would let an attacker who touches a decoy repeatedly *lower* its own score.
#>
function Measure-TripwireDecoyPuritySignal {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowNull()] $Decoy,
        [Parameter(Mandatory)] $Policy
    )

    $weight = $Policy.Weights.DecoyPurity

    if ($null -eq $Decoy) {
        return New-TripwireSignal -Name 'DecoyPurity' -Weight $weight -Available $false `
            -Rationale 'The touched object is not in the decoy inventory, so its purity is unknown.'
    }

    $uses = $Decoy.legitimateUseCount
    if ($null -eq $uses) { $uses = 0 }
    $uses = [int]$uses

    foreach ($tier in $Policy.PurityTiers) {
        if ($uses -le $tier.MaxUses) {
            $rationale = if ($uses -eq 0) {
                "Decoy '$($Decoy.displayName)' has no recorded legitimate use since it was planted."
            }
            else {
                "Decoy '$($Decoy.displayName)' has $uses recorded legitimate use(s); a touch is weaker evidence."
            }
            return New-TripwireSignal -Name 'DecoyPurity' -Weight $weight -Raw $tier.Raw -Rationale $rationale
        }
    }

    return New-TripwireSignal -Name 'DecoyPurity' -Weight $weight -Raw 0.0 `
        -Rationale "Decoy '$($Decoy.displayName)' has $uses recorded legitimate uses. It is contaminated and carries no evidential weight; re-plant it."
}

<#
.SYNOPSIS
    Signal (b): is the origin of this touch anomalous for this tenant?

.DESCRIPTION
    Three components, strongest wins:

      1. Impossible travel -- the same actor was seen elsewhere in the baseline and the
         implied ground speed exceeds the policy limit. Decisive when it fires.
      2. A country the tenant has never signed in from, or one that accounts for less
         than RareCountryShare of baseline volume.
      3. An autonomous system the tenant has never used, or a rare one. Weaker than
         country on its own: cloud egress legitimately moves between ASNs.

    With no baseline, this is WITHHELD. The temptation is to treat an unknown origin as
    anomalous, and that is backwards -- on a tenant with no history, every origin is
    unknown, and the detector would fire on all of them at once on day one.
#>
function Measure-TripwireOriginSignal {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Touch,
        [AllowNull()] $Baseline,
        [Parameter(Mandatory)] $Policy
    )

    $weight = $Policy.Weights.OriginAnomaly

    $total = if ($null -ne $Baseline) { $Baseline.totalSignIns } else { $null }
    if ($null -eq $Baseline -or $null -eq $total -or [int]$total -le 0) {
        return New-TripwireSignal -Name 'OriginAnomaly' -Weight $weight -Available $false `
            -Rationale 'No tenant baseline of sign-in origins, so "unusual origin" has no meaning yet. Run Get-TripwireBaseline first.'
    }
    $total = [int]$total

    # 1. Impossible travel against the actor's last known position.
    $lastSeen = Get-TripwireMapValue -Map $Baseline.actorLastSeen -Key ([string]$Touch.actor.id)
    if ($null -ne $lastSeen -and $null -ne $Touch.latitude -and $null -ne $lastSeen.latitude) {
        $km = Get-TripwireDistanceKm -Lat1 $lastSeen.latitude -Lon1 $lastSeen.longitude `
            -Lat2 $Touch.latitude -Lon2 $Touch.longitude
        $hours = ((ConvertTo-TripwireUtc $Touch.timestamp) - (ConvertTo-TripwireUtc $lastSeen.timestamp)).TotalHours
        if ($null -ne $km -and $hours -gt 0) {
            $kph = $km / $hours
            if ($kph -gt $Policy.ImpossibleTravelKph) {
                return New-TripwireSignal -Name 'OriginAnomaly' -Weight $weight -Raw 1.0 -Rationale (
                    'Impossible travel: {0} km from the previous sign-in in {1} h implies at least {2} km/h (limit {3}).' -f `
                        [Math]::Round($km), [Math]::Round($hours, 2), [Math]::Round($kph), $Policy.ImpossibleTravelKph)
            }
        }
    }

    # No origin enrichment at all (directory audits carry none) means the origin CANNOT be
    # judged. Scoring that as 0.0 would report "normal origin" about an origin nobody saw.
    $hasCountry = -not [string]::IsNullOrWhiteSpace([string]$Touch.country)
    $hasAsn = -not [string]::IsNullOrWhiteSpace([string]$Touch.asn)
    if (-not $hasCountry -and -not $hasAsn) {
        return New-TripwireSignal -Name 'OriginAnomaly' -Weight $weight -Available $false `
            -Rationale 'This log source carries no country or autonomous-system enrichment, so the origin cannot be compared with the tenant baseline.'
    }

    $best = 0.0
    $reason = "Origin $($Touch.country)/AS$($Touch.asn) is normal for this tenant."

    # 2. Country.
    $country = [string]$Touch.country
    if ($hasCountry) {
        $seen = Get-TripwireMapValue -Map $Baseline.countries -Key $country
        if ($null -eq $seen -or [int]$seen -le 0) {
            $best = $Policy.OriginRaw.UnseenCountry
            $reason = "Country '$country' has never appeared in $total baseline sign-ins."
        }
        elseif (([double]$seen / $total) -lt $Policy.RareCountryShare) {
            $best = $Policy.OriginRaw.RareCountry
            $reason = ('Country ''{0}'' accounts for {1:P2} of baseline sign-ins.' -f $country, ([double]$seen / $total))
        }
    }

    # 3. Autonomous system.
    $asn = [string]$Touch.asn
    if ($hasAsn) {
        $seenAsn = Get-TripwireMapValue -Map $Baseline.asns -Key $asn
        $asnRaw = 0.0
        $asnReason = $null
        if ($null -eq $seenAsn -or [int]$seenAsn -le 0) {
            $asnRaw = $Policy.OriginRaw.UnseenAsn
            $asnReason = "AS$asn has never appeared in $total baseline sign-ins."
        }
        elseif (([double]$seenAsn / $total) -lt $Policy.RareAsnShare) {
            $asnRaw = $Policy.OriginRaw.RareAsn
            $asnReason = ('AS{0} accounts for {1:P2} of baseline sign-ins.' -f $asn, ([double]$seenAsn / $total))
        }
        if ($asnRaw -gt $best) { $best = $asnRaw; $reason = $asnReason }
    }

    return New-TripwireSignal -Name 'OriginAnomaly' -Weight $weight -Raw $best -Rationale $reason
}

<#
.SYNOPSIS
    Signal (c): how many DISTINCT decoys did this actor touch inside the correlation window?

.DESCRIPTION
    One decoy touched once is a lead. Several decoys touched by one actor in an hour is
    enumeration -- nothing legitimate walks a set of objects that no legitimate process
    knows about. This is the strongest behavioural signal in the engine and the reason a
    deployment should plant more than one decoy.

    The count is of distinct decoy ids, never of events. An attacker retrying one decoy
    fifty times must not look like a fan-out across fifty decoys.
#>
function Measure-TripwireFanOutSignal {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [int] $DistinctDecoyCount,
        [Parameter(Mandatory)] $Policy
    )

    $weight = $Policy.Weights.CrossDecoyFanOut
    $raw = 0.0
    foreach ($tier in $Policy.FanOutTiers) {
        if ($DistinctDecoyCount -ge $tier.MinDecoys) { $raw = $tier.Raw }
    }

    $rationale = if ($DistinctDecoyCount -le 1) {
        'A single decoy was touched by this actor inside the correlation window; no fan-out.'
    }
    else {
        "$DistinctDecoyCount distinct decoys were touched by the same actor inside the correlation window -- consistent with enumeration."
    }

    return New-TripwireSignal -Name 'CrossDecoyFanOut' -Weight $weight -Raw $raw -Rationale $rationale
}

<#
.SYNOPSIS
    Signal (d): how unusual is this hour for this tenant?

.DESCRIPTION
    Scored against the tenant's own 24-hour sign-in histogram, not against an assumption
    about office hours: a tenant whose staff work nights must not be permanently suspicious
    of itself.

    This carries the smallest weight on purpose. Legitimate administrators do work at
    03:00, and a detector that treats the hour as strong evidence trains its operators to
    dismiss it. See docs/scoring.md for the invariant that keeps it honest: no single
    signal, this one included, can reach the containment band alone.
#>
function Measure-TripwireOffHoursSignal {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Touch,
        [AllowNull()] $Baseline,
        [Parameter(Mandatory)] $Policy
    )

    $weight = $Policy.Weights.OffHours
    $hist = if ($null -ne $Baseline) { $Baseline.hourHistogram } else { $null }

    if ($null -eq $hist -or @($hist).Count -ne 24) {
        return New-TripwireSignal -Name 'OffHours' -Weight $weight -Available $false `
            -Rationale 'No 24-hour baseline histogram, so this hour cannot be compared with the tenant norm.'
    }

    $values = @($hist | ForEach-Object { [double]$_ })
    $peak = ($values | Measure-Object -Maximum).Maximum
    if ($peak -le 0) {
        return New-TripwireSignal -Name 'OffHours' -Weight $weight -Available $false `
            -Rationale 'The baseline histogram is empty, so no hour is more normal than another.'
    }

    $hour = (ConvertTo-TripwireUtc $Touch.timestamp).Hour
    $density = $values[$hour] / $peak
    $raw = 1.0 - $density

    return New-TripwireSignal -Name 'OffHours' -Weight $weight -Raw $raw -Rationale (
        '{0:00}:00 UTC runs at {1:P0} of this tenant''s busiest hour.' -f $hour, $density)
}

<#
.SYNOPSIS
    Hard suppression rules, evaluated before any signal.

.DESCRIPTION
    These are the known-benign causes of a decoy touch. They return a reason string, and a
    suppressed trip scores zero regardless of how anomalous it looks -- which is the point:
    a scanner sweeping every object in the directory at 04:00 from a datacentre ASN would
    otherwise light up every signal at once.

    Returns $null when nothing suppresses the event.
#>
function Test-TripwireSuppression {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Touch,
        [AllowNull()] $Decoy,
        [AllowNull()] $Baseline,
        [Parameter(Mandatory)] $Policy
    )

    $actorId = [string]$Touch.actor.id

    # 1. Operator-maintained allowlist: the tenant's own scanners, CMDB sync, DLP tooling.
    if ($null -ne $Baseline -and $null -ne $Baseline.suppressedActors) {
        foreach ($allowed in @($Baseline.suppressedActors)) {
            if (-not [string]::IsNullOrWhiteSpace($actorId) -and
                [string]$allowed -eq $actorId) {
                return "Actor $actorId is on the tenant suppression allowlist."
            }
        }
    }

    # 2. Provisioning self-noise. Planting a decoy writes an audit record in which the
    #    planter touches the decoy. Without this rule every deployment starts with a page.
    if ($null -ne $Decoy -and $null -ne $Decoy.plantedAt -and -not [string]::IsNullOrWhiteSpace([string]$Decoy.plantedBy)) {
        $sincePlant = ((ConvertTo-TripwireUtc $Touch.timestamp) - (ConvertTo-TripwireUtc $Decoy.plantedAt)).TotalMinutes
        $planter = [string]$Decoy.plantedBy
        $isPlanter = ($planter -eq $actorId) -or ($planter -eq [string]$Touch.actor.upn)
        if ($isPlanter -and $sincePlant -ge 0 -and $sincePlant -le $Policy.ProvisioningGraceMinutes) {
            return "Within the $($Policy.ProvisioningGraceMinutes)-minute provisioning window and performed by the planter ($planter)."
        }
    }

    return $null
}
