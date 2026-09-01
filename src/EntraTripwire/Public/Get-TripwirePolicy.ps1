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

    Two invariants fall out of these numbers and are enforced by tests:

      * No single signal can reach the High band alone (max single = 40 < 75). One
        anomaly is never enough to act on.
      * A contaminated decoy (more than 10 recorded legitimate uses) can never reach the
        High band, because the remaining weights total 0.60. Containment cannot fire on a
        decoy that has stopped being a decoy.

.PARAMETER Override
    A hashtable merged over the defaults, e.g. @{ ImpossibleTravelKph = 1200 }. Only
    top-level keys are replaced; pass a whole sub-object to change part of one.

.EXAMPLE
    Get-TripwirePolicy | ConvertTo-Json -Depth 6
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
    }

    if ($Override) {
        foreach ($key in $Override.Keys) { $policy[$key] = $Override[$key] }
    }

    return [pscustomobject]$policy
}
