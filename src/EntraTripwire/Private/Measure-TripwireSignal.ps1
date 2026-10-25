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
    A number out of a hand-maintained file, or $null if it is not one.

.DESCRIPTION
    Baselines and decoy records are JSON files an operator is told to edit: the suppression
    allowlist, legitimateUseCount, a corrected sign-in total. So every number the engine
    reads out of them can arrive as a word, and the casts that read them -- [int], [double],
    and the [double] parameter binding in Get-TripwireDistanceKm -- all THROW on one.

    They throw inside a signal, which is the worst place for it. Scoring runs per touch
    inside Invoke-TripwireAnalysis, so one bad character in one baseline field aborted the
    whole batch: a run that found intrusions returned nothing, and nothing is what a quiet
    tenant returns. Reading through here turns that into a withheld signal on a trip the
    operator can still see.

    Test-TripwireNumber does the deciding (it lives with Assert-TripwirePolicy, which has
    to answer the same question about a policy), so "is this a number" cannot come to two
    different answers in two places. [double] rather than [int] on the way out: [int] on a
    count larger than 2^31 throws too, which is the same class of defect one cast along.
#>
function ConvertTo-TripwireNumberOrNull {
    [CmdletBinding()]
    [OutputType([double])]
    param([AllowNull()] $Value)

    if (-not (Test-TripwireNumber $Value)) { return $null }
    return [double]$Value
}

<#
.SYNOPSIS
    Is the tenant baseline still a description of this tenant?

.DESCRIPTION
    Get-TripwireBaseline has always stamped generatedAt into the file, and until now
    nothing read it. A baseline from six months ago was used in silence, which means
    "unusual country" and "outside working hours" were scored against a tenant that had
    since hired, moved, changed its egress and retired an office. Both of those signals
    are only as meaningful as the history behind them.

    Age is measured against the TOUCH being scored rather than against the clock. That is
    not a convenience: re-analysing last month's logs should compare them with the baseline
    that was current for them, and a baseline built after the event is not stale at all --
    its history covers the period the touch came from. Only a touch with no usable time
    falls back to the clock, since there is nothing else to anchor it to.

    Two limits, both policy: a warning age and a stale age. Past the stale age the caller
    WITHHOLDS. Withholding is a real cost -- it lowers the score and marks the trip
    degraded -- and that is the correct direction: a signal computed against an obsolete
    baseline is not weaker evidence, it is evidence about a different tenant.

    Returns Known = $false when the age cannot be established, and Stale = $true with it.
    An age nobody can establish is not freshness. This is the same rule the purity signal
    applies to an unreadable legitimateUseCount, and the reason it has to be written down
    is that PowerShell answers it the other way for free: `145 -gt $null` is $true, so a
    missing limit would decide this by accident, in whichever direction the comparison
    happened to be typed.
#>
function Test-TripwireBaselineFreshness {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowNull()] $Baseline,
        [AllowNull()] $AsOf,
        [Parameter(Mandatory)] $Policy
    )

    $verdict = {
        param($known, $stale, $warn, $age, $reason)
        [pscustomobject]@{ Known = $known; Stale = $stale; Warn = $warn; AgeDays = $age; Reason = $reason }
    }

    # No baseline at all is a different answer from a stale one, and the callers already
    # withhold for it with a message that tells the operator to build one.
    if ($null -eq $Baseline) { return & $verdict $false $false $false $null 'there is no baseline.' }

    $warnAge = ConvertTo-TripwireNumberOrNull $Policy.BaselineWarnAgeDays
    $staleAge = ConvertTo-TripwireNumberOrNull $Policy.BaselineStaleAgeDays
    if ($null -eq $warnAge -or $null -eq $staleAge) {
        return & $verdict $false $true $true $null (
            'the policy carries no usable BaselineWarnAgeDays or BaselineStaleAgeDays, so the age of the baseline cannot be judged at all. Start from Get-TripwirePolicy and override what you need.')
    }

    $generatedAt = ConvertTo-TripwireUtcOrNull $Baseline.generatedAt
    if ($null -eq $generatedAt) {
        return & $verdict $false $true $true $null (
            "the baseline records generatedAt as '$($Baseline.generatedAt)', so how old it is cannot be established. Rebuild it with Get-TripwireBaseline -Build -Save.")
    }

    $reference = ConvertTo-TripwireUtcOrNull $AsOf
    if ($null -eq $reference) { $reference = [DateTime]::UtcNow }

    $age = ($reference - $generatedAt).TotalDays
    if ($age -lt 0) { $age = 0.0 }

    $stale = ($age -gt $staleAge)
    $reason = if ($stale) {
        'the baseline was generated {0:N1} day(s) earlier, past the {1}-day limit, so it describes a tenant this touch can no longer be compared with. Rebuild it with Get-TripwireBaseline -Build -Save.' -f $age, $staleAge
    }
    else { '' }

    return & $verdict $true $stale ($age -ge $warnAge) $age $reason
}

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

    # legitimateUseCount is the one field in the inventory the operator is told to edit by
    # hand (see .DESCRIPTION), which makes it the one field that can arrive as 'three'.
    # [int] on that throws, and it throws inside the DOMINANT signal, so one typo in a
    # JSON file took down scoring for every touch. Unreadable is not zero: a purity we
    # cannot establish is withheld, which marks the trip degraded and keeps containment
    # off it, rather than asserting the decoy is pristine.
    $uses = 0
    if ($null -ne $Decoy.legitimateUseCount) {
        $parsed = 0
        if (-not [int]::TryParse([string]$Decoy.legitimateUseCount, [ref] $parsed)) {
            return New-TripwireSignal -Name 'DecoyPurity' -Weight $weight -Available $false -Rationale (
                "Decoy '$($Decoy.displayName)' records legitimateUseCount as '$($Decoy.legitimateUseCount)', which is not a whole number. Its purity cannot be established; fix the inventory record.")
        }
        $uses = $parsed
    }
    if ($uses -lt 0) { $uses = 0 }

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

    # totalSignIns is a number in a file an operator edits, so it can arrive as a word.
    # Unreadable is its own answer: it is not a total of zero and it is not a missing
    # baseline, and [int] on it threw from inside this signal on every touch.
    $declaredTotal = if ($null -ne $Baseline) { $Baseline.totalSignIns } else { $null }
    $total = ConvertTo-TripwireNumberOrNull $declaredTotal
    if ($null -ne $Baseline -and $null -ne $declaredTotal -and $null -eq $total) {
        return New-TripwireSignal -Name 'OriginAnomaly' -Weight $weight -Available $false -Rationale (
            "The baseline records totalSignIns as '$declaredTotal', which is not a number, so no origin can be measured as a share of it. Rebuild the baseline.")
    }

    if ($null -eq $Baseline -or $null -eq $total -or $total -le 0) {
        return New-TripwireSignal -Name 'OriginAnomaly' -Weight $weight -Available $false `
            -Rationale 'No tenant baseline of sign-in origins, so "unusual origin" has no meaning yet. Run Get-TripwireBaseline first.'
    }

    # Both times must resolve. Subtracting a DateTime from $null throws, which would
    # abandon the whole batch over one record that merely lacks a usable timestamp.
    $touchAt = ConvertTo-TripwireUtcOrNull $Touch.timestamp

    # An origin is only unusual relative to a history, and a history has a shelf life.
    # Scoring against an expired one is not weaker evidence: it is evidence about the
    # tenant as it was, which is why this withholds rather than discounts.
    $freshness = Test-TripwireBaselineFreshness -Baseline $Baseline -AsOf $touchAt -Policy $Policy
    if ($freshness.Stale) {
        return New-TripwireSignal -Name 'OriginAnomaly' -Weight $weight -Available $false -Rationale (
            'The origin cannot be compared with this tenant: {0}' -f $freshness.Reason)
    }

    # 1. Impossible travel against the actor's last known position.
    $lastSeen = Get-TripwireMapValue -Map $Baseline.actorLastSeen -Key ([string]$Touch.actor.id)
    if ($null -ne $lastSeen) {
        # Coordinates come from JSON and from the same hand-editable baseline, and
        # Get-TripwireDistanceKm binds them to [double]: a latitude recorded as 'north'
        # throws on PARAMETER BINDING, before any guard inside that function can run.
        # Resolved to numbers or $null first, and $null there withholds the component --
        # "no location" must never read as "same city".
        $km = Get-TripwireDistanceKm `
            -Lat1 (ConvertTo-TripwireNumberOrNull $lastSeen.latitude) `
            -Lon1 (ConvertTo-TripwireNumberOrNull $lastSeen.longitude) `
            -Lat2 (ConvertTo-TripwireNumberOrNull $Touch.latitude) `
            -Lon2 (ConvertTo-TripwireNumberOrNull $Touch.longitude)
        $seenAt = ConvertTo-TripwireUtcOrNull $lastSeen.timestamp
        $hours = if ($null -ne $touchAt -and $null -ne $seenAt) { ($touchAt - $seenAt).TotalHours } else { 0 }
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

    # A baseline entry that is PRESENT but unreadable is not the same as an absent one.
    # Absent means the tenant has never been seen here, which scores the full anomaly;
    # claiming that from a corrupt record manufactures evidence. Collected here and
    # answered at the bottom.
    $unreadable = [System.Collections.Generic.List[string]]::new()

    # 2. Country.
    $country = [string]$Touch.country
    if ($hasCountry) {
        $declared = Get-TripwireMapValue -Map $Baseline.countries -Key $country
        $seen = ConvertTo-TripwireNumberOrNull $declared
        if ($null -ne $declared -and $null -eq $seen) {
            $unreadable.Add("the baseline count for country '$country' is '$declared', which is not a number")
        }
        elseif ($null -eq $seen -or $seen -le 0) {
            $best = $Policy.OriginRaw.UnseenCountry
            $reason = "Country '$country' has never appeared in $total baseline sign-ins."
        }
        elseif (($seen / $total) -lt $Policy.RareCountryShare) {
            $best = $Policy.OriginRaw.RareCountry
            $reason = ('Country ''{0}'' accounts for {1:P2} of baseline sign-ins.' -f $country, ($seen / $total))
        }
    }

    # 3. Autonomous system.
    $asn = [string]$Touch.asn
    if ($hasAsn) {
        $declaredAsn = Get-TripwireMapValue -Map $Baseline.asns -Key $asn
        $seenAsn = ConvertTo-TripwireNumberOrNull $declaredAsn
        $asnRaw = 0.0
        $asnReason = $null
        if ($null -ne $declaredAsn -and $null -eq $seenAsn) {
            $unreadable.Add("the baseline count for AS$asn is '$declaredAsn', which is not a number")
        }
        elseif ($null -eq $seenAsn -or $seenAsn -le 0) {
            $asnRaw = $Policy.OriginRaw.UnseenAsn
            $asnReason = "AS$asn has never appeared in $total baseline sign-ins."
        }
        elseif (($seenAsn / $total) -lt $Policy.RareAsnShare) {
            $asnRaw = $Policy.OriginRaw.RareAsn
            $asnReason = ('AS{0} accounts for {1:P2} of baseline sign-ins.' -f $asn, ($seenAsn / $total))
        }
        if ($asnRaw -gt $best) { $best = $asnRaw; $reason = $asnReason }
    }

    # Never report a normal origin on the strength of a comparison that could not be made.
    # A positive finding stands on its own -- the score is a floor and more evidence could
    # only raise it -- but a zero resting on an unreadable baseline entry is the sentence
    # an operator acts on by closing the alert.
    if ($best -le 0 -and $unreadable.Count -gt 0) {
        return New-TripwireSignal -Name 'OriginAnomaly' -Weight $weight -Available $false -Rationale (
            'The origin cannot be compared with the tenant baseline: {0}. Rebuild the baseline.' -f (@($unreadable) -join '; '))
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

    # Hand-editable JSON again, and [double]'noon' throws -- here, for every touch in the
    # batch. One bucket that is not a number also makes the peak wrong, and the peak is the
    # denominator of every hour's density, so the whole histogram is withheld rather than
    # 23 hours of it being scored against a corrupt maximum.
    $values = [System.Collections.Generic.List[double]]::new()
    foreach ($bucket in @($hist)) {
        $parsed = ConvertTo-TripwireNumberOrNull $bucket
        if ($null -eq $parsed) {
            return New-TripwireSignal -Name 'OffHours' -Weight $weight -Available $false -Rationale (
                "The baseline hour histogram holds '$bucket', which is not a number, so no hour can be compared with the tenant norm. Rebuild the baseline.")
        }
        $values.Add($parsed)
    }

    $peak = ($values | Measure-Object -Maximum).Maximum
    if ($peak -le 0) {
        return New-TripwireSignal -Name 'OffHours' -Weight $weight -Available $false `
            -Rationale 'The baseline histogram is empty, so no hour is more normal than another.'
    }

    # A touch with no usable timestamp has no hour to compare. Indexing the histogram with
    # the $null that came back raised "the array index evaluated to null" and killed the
    # run; treating it as hour 0 would have been worse -- 00:00 is the deadest hour in most
    # tenants, so an absent timestamp would have scored as maximum off-hours anomaly.
    $at = ConvertTo-TripwireUtcOrNull $Touch.timestamp
    if ($null -eq $at) {
        return New-TripwireSignal -Name 'OffHours' -Weight $weight -Available $false `
            -Rationale 'This record carries no usable timestamp, so the hour it happened in cannot be compared with the tenant norm.'
    }

    # "Off hours for this tenant" is a claim about a tenant that was measured at some
    # point. Past the policy's stale age the histogram describes the working pattern of a
    # tenant that has since changed shift, so it is withheld rather than believed.
    $freshness = Test-TripwireBaselineFreshness -Baseline $Baseline -AsOf $at -Policy $Policy
    if ($freshness.Stale) {
        return New-TripwireSignal -Name 'OffHours' -Weight $weight -Available $false -Rationale (
            'This hour cannot be compared with the tenant norm: {0}' -f $freshness.Reason)
    }

    $hour = $at.Hour
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
    #    Both times must resolve. This rule HIDES evidence, so when it cannot establish
    #    that the touch really falls inside the grace window it must decline to suppress --
    #    a suppression rule that fires on an unknown is a way to lose an intrusion quietly.
    $touchAt = ConvertTo-TripwireUtcOrNull $Touch.timestamp
    $plantedAt = if ($null -ne $Decoy) { ConvertTo-TripwireUtcOrNull $Decoy.plantedAt } else { $null }
    if ($null -ne $touchAt -and $null -ne $plantedAt -and -not [string]::IsNullOrWhiteSpace([string]$Decoy.plantedBy)) {
        $sincePlant = ($touchAt - $plantedAt).TotalMinutes
        $planter = [string]$Decoy.plantedBy
        $isPlanter = ($planter -eq $actorId) -or ($planter -eq [string]$Touch.actor.upn)
        if ($isPlanter -and $sincePlant -ge 0 -and $sincePlant -le $Policy.ProvisioningGraceMinutes) {
            return "Within the $($Policy.ProvisioningGraceMinutes)-minute provisioning window and performed by the planter ($planter)."
        }
    }

    return $null
}
