<#
.SYNOPSIS
    Correlate a set of touches into actors, then score every touch.

.DESCRIPTION
    Fan-out is the only signal that cannot be computed from a single touch, so it is
    computed here, over the whole set, before anything is scored.

    The correlation is per actor and per sliding window: for each touch, count the DISTINCT
    decoys the same actor touched within CorrelationWindowMinutes either side. Distinct
    decoys, never events -- an attacker retrying one decoy fifty times must not look like a
    sweep across fifty decoys.

    Touches whose actor cannot be identified at all (no directory object id, no source
    address) are never correlated with anything. Bucketing anonymous events together would
    manufacture fan-out out of unrelated noise, and fan-out is what carries a trip into the
    band where containment becomes eligible.

    A touch whose timestamp cannot be resolved is in the same position: it cannot be placed
    in any window, so it is scored alone at fan-out 1 and the signals that need a clock
    withhold themselves. It is NOT dropped and it does not stop the batch. Before this was
    explicit, one record with no createdDateTime raised a terminating error here and took
    every other scored trip in the run with it -- a run that found intrusions returned
    nothing, and nothing is exactly what a quiet tenant returns.

.PARAMETER Touch
    Normalised touches from Watch-TripwireActivity.

.PARAMETER Decoy
    The decoy inventory.

.PARAMETER Baseline
    Tenant baseline. Optional; without it the affected signals are withheld.

.PARAMETER Policy
    Scoring policy. Defaults to Get-TripwirePolicy.

.EXAMPLE
    Invoke-TripwireAnalysis -Touch $touches -Decoy (Get-TripwireDecoy) -Baseline (Get-TripwireBaseline) |
        Sort-Object Confidence -Descending | Format-Table Confidence, Band, DecoyName, ActorLabel
#>
function Invoke-TripwireAnalysis {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Touch,
        [AllowEmptyCollection()] [object[]] $Decoy = @(),
        [AllowNull()] $Baseline,
        $Policy
    )

    $Policy = Resolve-TripwirePolicy -Policy $Policy

    $decoyById = @{}
    foreach ($d in $Decoy) { $decoyById[[string]$d.id] = $d }

    $windowTicks = [TimeSpan]::FromMinutes($Policy.CorrelationWindowMinutes).Ticks

    # One pass to resolve each touch's identity and its time. Both were previously
    # recomputed inside the inner loop, which made the parse cost quadratic: 2,000 touches
    # over 20 actors took 10.3 s, almost all of it re-parsing the same timestamps.
    $entries = [System.Collections.Generic.List[object]]::new()
    $byActor = @{}
    foreach ($t in $Touch) {
        $key = Get-TripwireActorKey -Touch $t
        $when = ConvertTo-TripwireUtcOrNull $t.timestamp
        $entry = [pscustomobject]@{
            Touch   = $t
            Ticks   = if ($null -ne $when) { $when.Ticks } else { $null }
            DecoyId = [string]$t.decoyId
            Count   = 1
        }
        $entries.Add($entry)

        # Correlation needs BOTH an identifiable actor and a placeable time. Missing
        # either, the touch is scored alone rather than folded into somebody else's window.
        if ($null -ne $key -and $null -ne $when) {
            if (-not $byActor.ContainsKey($key)) { $byActor[$key] = [System.Collections.Generic.List[object]]::new() }
            $byActor[$key].Add($entry)
        }
    }

    # Per actor: sort once, then sweep the window with two pointers. The distinct count is
    # over decoy IDS, never events -- an attacker retrying one decoy fifty times must not
    # look like a sweep across fifty decoys.
    foreach ($bucket in $byActor.Values) {
        $sorted = @($bucket | Sort-Object -Property Ticks)
        $lo = 0
        $hi = -1
        for ($i = 0; $i -lt $sorted.Count; $i++) {
            $centre = $sorted[$i].Ticks
            while ($lo -lt $sorted.Count -and ($centre - $sorted[$lo].Ticks) -gt $windowTicks) { $lo++ }
            if ($hi -lt $i) { $hi = $i }
            while (($hi + 1) -lt $sorted.Count -and ($sorted[$hi + 1].Ticks - $centre) -le $windowTicks) { $hi++ }

            $distinct = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            for ($j = $lo; $j -le $hi; $j++) { [void] $distinct.Add($sorted[$j].DecoyId) }
            $sorted[$i].Count = [Math]::Max(1, $distinct.Count)
        }
    }

    foreach ($entry in $entries) {
        Measure-TripwireConfidence -Touch $entry.Touch -Decoy $decoyById[$entry.DecoyId] `
            -Baseline $Baseline -DistinctDecoyCount $entry.Count -Policy $Policy
    }
}
