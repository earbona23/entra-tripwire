<#
.SYNOPSIS
    Great-circle distance between two coordinates, in kilometres.

.DESCRIPTION
    Used only by the impossible-travel component of the origin signal. Haversine is
    deliberate: it under-estimates the real path a traveller must fly, so any speed it
    derives is a LOWER bound. An impossible-travel verdict built on a lower bound cannot
    be an artefact of the distance model -- if this says 4,000 km/h, the real figure is
    at least that.

    Returns $null when either coordinate pair is missing, so the caller can withhold the
    signal instead of inventing one. Graph omits location on sign-ins from private ranges
    and from some non-interactive flows, and "no location" must never read as "same city".
#>
function Get-TripwireDistanceKm {
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [AllowNull()] [System.Nullable[double]] $Lat1,
        [AllowNull()] [System.Nullable[double]] $Lon1,
        [AllowNull()] [System.Nullable[double]] $Lat2,
        [AllowNull()] [System.Nullable[double]] $Lon2
    )

    if ($null -eq $Lat1 -or $null -eq $Lon1 -or $null -eq $Lat2 -or $null -eq $Lon2) { return $null }

    $earthRadiusKm = 6371.0088
    $toRad = [Math]::PI / 180.0

    $dLat = ([double]$Lat2 - [double]$Lat1) * $toRad
    $dLon = ([double]$Lon2 - [double]$Lon1) * $toRad

    $a = [Math]::Sin($dLat / 2) * [Math]::Sin($dLat / 2) +
         [Math]::Cos([double]$Lat1 * $toRad) * [Math]::Cos([double]$Lat2 * $toRad) *
         [Math]::Sin($dLon / 2) * [Math]::Sin($dLon / 2)

    $c = 2 * [Math]::Atan2([Math]::Sqrt($a), [Math]::Sqrt(1 - $a))
    return [Math]::Round($earthRadiusKm * $c, 3)
}
