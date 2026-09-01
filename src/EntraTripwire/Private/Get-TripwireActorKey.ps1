<#
.SYNOPSIS
    The identity used to correlate several touches into one actor.

.DESCRIPTION
    Correlation prefers the directory object id of whoever performed the action. When
    Graph does not give one -- an unauthenticated probe, a failed sign-in against a
    username that does not resolve -- the source address is the fallback, which is weaker
    but still correlates a single spray across several decoys.

    When neither exists the function returns $null, and the caller must NOT correlate.
    Grouping every anonymous event under one bucket would manufacture fan-out out of
    unrelated noise, which is the single most dangerous false positive this tool can have:
    fan-out is the signal that pushes a trip into the containment band.
#>
function Get-TripwireActorKey {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Touch)

    $actor = $Touch.actor
    if ($null -ne $actor -and -not [string]::IsNullOrWhiteSpace([string]$actor.id)) {
        return 'actor:' + ([string]$actor.id).ToLowerInvariant()
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Touch.ip)) {
        return 'ip:' + ([string]$Touch.ip)
    }
    return $null
}
