<#
.SYNOPSIS
    The scoring policy: weights, tiers, thresholds and suppression parameters.

.DESCRIPTION
    Returned as data, not buried in the engine, so an operator can read the calibration,
    argue with it, and override it per deployment. Every number below is justified in
    docs/scoring.md; the short version:

      DecoyPurity      0.40  The dominant signal. A decoy nothing legitimate touches is
                             the entire premise -- if this one is weak, nothing else
                             should be able to carry a trip to containment.
      OriginAnomaly    0.25  Strong, but noisy on tenants with travelling staff and cloud
                             egress that moves between autonomous systems.
      CrossDecoyFanOut 0.25  The behavioural signal. Nothing legitimate walks a set of
                             objects that no legitimate process knows exists.
      OffHours         0.10  Deliberately weak. Real administrators work at 03:00, and a
                             detector that treats the hour as strong evidence teaches its
                             operators to close the alert.

    The weights sum to 1.00, so confidence is a percentage of the maximum obtainable
    evidence and two deployments' scores mean the same thing.

    BaselineWarnAgeDays (15) and BaselineStaleAgeDays (30) govern how long the tenant
    baseline is believed. Past the stale age the origin and off-hours signals withhold
    themselves instead of scoring a touch against a tenant that has moved on; the reasoning
    for both numbers is in the body of this function and in docs/scoring.md.

    Two invariants fall out of these numbers and are enforced by tests:

      * No single signal can reach the High band alone (max single = 40 < 75). One
        anomaly is never enough to act on.
      * A contaminated decoy (more than 10 recorded legitimate uses) can never reach the
        High band, because the remaining weights total 0.60. Containment cannot fire on a
        decoy that has stopped being a decoy.

.PARAMETER Override
    A hashtable merged over the defaults, e.g. @{ ImpossibleTravelKph = 1200 }. Only
    top-level keys are replaced; pass a whole sub-object carrying ALL of its members to
    change part of one.

    The result is validated and an incomplete one is refused by name, because the
    alternative is silent: a Threshold object handed in without its High member leaves
    that member $null, and `50 -ge $null` is $true in PowerShell -- so the typo bands
    every trip High, which is the only band containment acts on. Start from
    (Get-TripwirePolicy).Threshold and change what you need.

.EXAMPLE
    Get-TripwirePolicy | ConvertTo-Json -Depth 6

.EXAMPLE
    # Changing one threshold: copy the whole object, because the merge is by top-level key.
    $t = (Get-TripwirePolicy).Threshold
    Get-TripwirePolicy -Override @{ Threshold = [pscustomobject]@{ High = 80; Medium = $t.Medium } }
#>
function Get-TripwirePolicy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([hashtable] $Override)

    $policy = [ordered]@{
        Weights = [pscustomobject]@{
            DecoyPurity      = 0.40
            OriginAnomaly    = 0.25
            CrossDecoyFanOut = 0.25
            OffHours         = 0.10
        }

        # Confidence bands. High is the ONLY band containment will act on.
        Threshold = [pscustomobject]@{
            High   = 75
            Medium = 45
        }

        # Signal (a). Ordered from purest; the first tier whose MaxUses is not exceeded wins.
        PurityTiers = @(
            [pscustomobject]@{ MaxUses = 0; Raw = 1.00 }
            [pscustomobject]@{ MaxUses = 2; Raw = 0.50 }
            [pscustomobject]@{ MaxUses = 10; Raw = 0.20 }
        )

        # Signal (c). Highest matching MinDecoys wins. Two decoys is already a pattern;
        # four is a sweep.
        FanOutTiers = @(
            [pscustomobject]@{ MinDecoys = 2; Raw = 0.60 }
            [pscustomobject]@{ MinDecoys = 3; Raw = 0.85 }
            [pscustomobject]@{ MinDecoys = 4; Raw = 1.00 }
        )

        # Signal (b) components.
        OriginRaw = [pscustomobject]@{
            UnseenCountry = 1.00
            RareCountry   = 0.60
            UnseenAsn     = 0.80
            RareAsn       = 0.50
        }

        # A country or ASN below this share of baseline volume counts as rare.
        RareCountryShare = 0.01
        RareAsnShare     = 0.01

        # Ground speed above which two sign-ins cannot be the same human. 900 km/h is
        # roughly commercial cruise; the haversine distance it is computed from is a lower
        # bound, so a verdict here is not an artefact of the distance model.
        ImpossibleTravelKph = 900

        # Touches by the same actor inside this window are one incident for fan-out purposes.
        CorrelationWindowMinutes = 60

        # Planting a decoy makes the planter touch it. Without this the first run of every
        # deployment pages somebody.
        ProvisioningGraceMinutes = 15

        # How long a baseline describes the tenant it was built from. Past the warning age
        # the operator is told to rebuild it; past the stale age the two signals that
        # compare a touch against tenant history -- origin anomaly and off hours -- are
        # WITHHELD rather than scored against a tenant that no longer exists.
        #
        # 15 days to warn, which is half the stale age: notice is given at the point where
        # more of the baseline's believable life is behind it than ahead of it, and that
        # leaves a fortnight to rebuild before two signals start being withheld. A warning
        # at a week was the first calibration here and it was wrong for this module's own
        # reasons -- an operator who rebuilds monthly would see it three weeks in four, and
        # a message that is nearly always on is a message that gets filtered out.
        #
        # 30 days to withhold, because that is how long Entra retains sign-in logs on P1/P2
        # and it is also the default -Days of a build. A baseline older than that summarises
        # a period the tenant can no longer produce the evidence for: not one of the
        # sign-ins behind it is still in the log. A deployment that builds with a shorter
        # -Days should lower this to match, since its baseline describes less.
        #
        # Age is measured against the TOUCH being scored, not against the clock, so
        # re-analysing last month's logs compares them with the baseline that was current
        # for them, and the demo fixtures do not rot.
        BaselineWarnAgeDays = 15
        BaselineStaleAgeDays = 30
    }

    if ($Override) {
        foreach ($key in $Override.Keys) { $policy[$key] = $Override[$key] }
    }

    $result = [pscustomobject]$policy

    # An override is a whole-key replacement, so a sub-object handed in without one of its
    # members leaves that member $null -- and a $null threshold bands every trip High,
    # because `50 -ge $null` is $true in PowerShell. The override is validated here, at the
    # moment it is made, rather than discovered later as a detector that contains everything.
    #
    # Only when an override was given. The defaults above are literals in this file and
    # tests/Scoring.Tests.ps1 asserts their shape; re-walking them on every call cost 7 ms
    # a time, and Measure-TripwireConfidence builds a default policy once per touch.
    if ($Override) { Assert-TripwirePolicy -Policy $result }

    return $result
}
