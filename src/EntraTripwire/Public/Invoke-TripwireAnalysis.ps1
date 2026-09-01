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

    if (-not $Policy) { $Policy = Get-TripwirePolicy }

    $decoyById = @{}
    foreach ($d in $Decoy) { $decoyById[[string]$d.id] = $d }

    $window = [TimeSpan]::FromMinutes($Policy.CorrelationWindowMinutes)

    # Group by actor once; anonymous touches get a unique key each so they group alone.
    $byActor = @{}
    $anonymous = 0
    foreach ($t in $Touch) {
        $key = Get-TripwireActorKey -Touch $t
        if ($null -eq $key) {
            $anonymous++
            $key = "anon:$anonymous"
        }
        if (-not $byActor.ContainsKey($key)) { $byActor[$key] = [System.Collections.Generic.List[object]]::new() }
        $byActor[$key].Add($t)
    }

    foreach ($t in $Touch) {
        $key = Get-TripwireActorKey -Touch $t
        $distinct = 1
        if ($null -ne $key -and $byActor.ContainsKey($key)) {
            $near = @($byActor[$key] | Where-Object {
                    [Math]::Abs(((ConvertTo-TripwireUtc $_.timestamp) - (ConvertTo-TripwireUtc $t.timestamp)).TotalMinutes) -le $window.TotalMinutes
                })
            $distinct = @($near | ForEach-Object { [string]$_.decoyId } | Sort-Object -Unique).Count
            if ($distinct -lt 1) { $distinct = 1 }
        }

        Measure-TripwireConfidence -Touch $t -Decoy $decoyById[[string]$t.decoyId] `
            -Baseline $Baseline -DistinctDecoyCount $distinct -Policy $Policy
    }
}
