<#
.SYNOPSIS
    Score one decoy touch and return a trip.

.DESCRIPTION
    The false-positive suppression engine. It answers one question -- how confident are we
    that this touch is an adversary rather than the tenant tripping over its own furniture
    -- and it answers it in a way a human can audit: every signal reports its raw strength,
    its weight, and why.

    Order of operations, and it matters:

      1. Hard suppression. Known-benign causes (the allowlist, provisioning self-noise)
         short-circuit to a zero-confidence 'Suppressed' trip. A suppressed touch is still
         RETURNED, with its reason, because a suppression rule that hides evidence is
         indistinguishable from a bug that loses it.
      2. Four weighted signals, each of which may declare itself unavailable.
      3. Confidence = sum of weighted signals x 100, banded against the policy thresholds.

    A trip whose signals were not all available is marked Degraded. Its confidence is a
    FLOOR: withheld signals contribute zero and the weights are never renormalised, so a
    degraded score can only be lower than the truth, never higher. Invoke-TripwireContainment
    refuses to act on a degraded trip unless explicitly told otherwise.

.PARAMETER Touch
    One normalised touch, as produced by Watch-TripwireActivity.

.PARAMETER Decoy
    The decoy record the touch landed on.

.PARAMETER Baseline
    The tenant baseline from Get-TripwireBaseline. Optional: without it the origin and
    off-hours signals are withheld and the trip is marked degraded.

.PARAMETER DistinctDecoyCount
    How many distinct decoys this actor touched inside the correlation window. Supplied by
    Invoke-TripwireAnalysis, which sees the whole set; defaults to 1 when scoring a single
    touch in isolation.

.PARAMETER Policy
    Scoring policy. Defaults to Get-TripwirePolicy.

.EXAMPLE
    $trips = Watch-TripwireActivity -Demo
    $trips[0].Signals | Format-Table Name, Raw, Weight, Available, Rationale
#>
function Measure-TripwireConfidence {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Touch,
        [AllowNull()] $Decoy,
        [AllowNull()] $Baseline,
        [int] $DistinctDecoyCount = 1,
        $Policy
    )

    $Policy = Resolve-TripwirePolicy -Policy $Policy

    $decoyName = if ($null -ne $Decoy) { [string]$Decoy.displayName } else { "unknown decoy ($($Touch.decoyId))" }

    # Carried on the trip so containment never has to take the identity of the object it
    # is about to disable from a log record. Log records describe what an actor did and
    # are shaped by that actor; the local inventory is the only thing that knows what is
    # bait. Absent here means the decoy is not in the inventory, and containment refuses.
    $decoyObjectId = if ($null -ne $Decoy) { [string]$Decoy.objectId } else { '' }
    $decoyType = if ($null -ne $Decoy) { [string]$Decoy.type } else { '' }
    $actorLabel = if (-not [string]::IsNullOrWhiteSpace([string]$Touch.actor.displayName)) {
        [string]$Touch.actor.displayName
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$Touch.actor.upn)) { [string]$Touch.actor.upn }
    else { [string]$Touch.actor.id }

    $suppression = Test-TripwireSuppression -Touch $Touch -Decoy $Decoy -Baseline $Baseline -Policy $Policy
    if ($suppression) {
        return [pscustomobject]@{
            TouchId           = [string]$Touch.id
            DecoyId           = [string]$Touch.decoyId
            DecoyName         = $decoyName
            DecoyObjectId     = $decoyObjectId
            DecoyType         = $decoyType
            ActorLabel        = $actorLabel
            ActorKey          = Get-TripwireActorKey -Touch $Touch
            Touch             = $Touch
            Confidence        = 0.0
            Band              = 'Suppressed'
            Degraded          = $false
            Withheld          = @()
            Signals           = @()
            SuppressionReason = $suppression
            DistinctDecoys    = $DistinctDecoyCount
        }
    }

    $signals = @(
        Measure-TripwireDecoyPuritySignal -Decoy $Decoy -Policy $Policy
        Measure-TripwireOriginSignal -Touch $Touch -Baseline $Baseline -Policy $Policy
        Measure-TripwireFanOutSignal -DistinctDecoyCount $DistinctDecoyCount -Policy $Policy
        Measure-TripwireOffHoursSignal -Touch $Touch -Baseline $Baseline -Policy $Policy
    )

    $total = 0.0
    foreach ($s in $signals) { $total += $s.Weighted }
    $confidence = [Math]::Round($total * 100, 1)

    $withheld = @($signals | Where-Object { -not $_.Available } | ForEach-Object { $_.Name })

    $band = if ($confidence -ge $Policy.Threshold.High) { 'High' }
    elseif ($confidence -ge $Policy.Threshold.Medium) { 'Medium' }
    else { 'Low' }

    [pscustomobject]@{
        TouchId           = [string]$Touch.id
        DecoyId           = [string]$Touch.decoyId
        DecoyName         = $decoyName
        DecoyObjectId     = $decoyObjectId
        DecoyType         = $decoyType
        ActorLabel        = $actorLabel
        ActorKey          = Get-TripwireActorKey -Touch $Touch
        Touch             = $Touch
        Confidence        = $confidence
        Band              = $band
        Degraded          = ($withheld.Count -gt 0)
        Withheld          = $withheld
        Signals           = $signals
        SuppressionReason = $null
        DistinctDecoys    = $DistinctDecoyCount
    }
}
