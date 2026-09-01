<#
.SYNOPSIS
    Normalise any timestamp to a UTC DateTime.

.DESCRIPTION
    Every time comparison in this module goes through here, and the reason is a bug this
    function exists to make impossible.

    Timestamps reach the engine from three places with three different .NET Kinds: a touch
    normalised in-process carries Kind=Utc, a decoy's plantedAt read back from JSON is a
    STRING, and a cast like [DateTime]'2026-06-15T09:00:00Z' produces Kind=Local -- it
    shifts the value into the machine's timezone. Subtract one from the other and the
    difference is wrong by the UTC offset, silently. On a machine at UTC-4 the
    15-minute provisioning-grace window becomes a window that can never match, so the
    first run of every deployment pages somebody about its own planting; on a machine at
    UTC+0 the same code is correct and the bug is invisible.

    Kind=Unspecified is treated as UTC, which is what Microsoft Graph returns.
#>
function ConvertTo-TripwireUtc {
    [CmdletBinding()]
    [OutputType([DateTime])]
    param([Parameter(Mandatory)] [AllowNull()] $Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [DateTime]) {
        switch ($Value.Kind) {
            'Utc' { return $Value }
            'Local' { return $Value.ToUniversalTime() }
            default { return [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        }
    }

    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }

    $parsed = [DateTimeOffset]::Parse(
        [string]$Value,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal)
    return $parsed.UtcDateTime
}
