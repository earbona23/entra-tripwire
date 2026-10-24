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

<#
.SYNOPSIS
    ConvertTo-TripwireUtc, but a timestamp that cannot be resolved returns $null instead of
    throwing.

.DESCRIPTION
    Graph omits properties rather than nulling them, and a log record that reaches this
    module with no usable timestamp is a fact about the tenant, not a reason to abandon
    the run. ConvertTo-TripwireUtc throws on an unparseable value, which is right for code
    that cannot proceed without a time; every scoring path that CAN proceed -- by
    withholding the signals that need a clock -- goes through this one instead.

    The failure mode this replaces is the worst one a detector has: a single malformed
    record raised a terminating error out of Invoke-TripwireAnalysis and took every other
    scored trip in the batch with it, so a run that found intrusions returned nothing and
    looked exactly like a quiet tenant.

    Returns $null for: $null, an empty string, and anything that does not parse as a date.
#>
function ConvertTo-TripwireUtcOrNull {
    [CmdletBinding()]
    [OutputType([DateTime])]
    param([Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] $Value)

    if ($null -eq $Value) { return $null }
    if (($Value -is [string]) -and [string]::IsNullOrWhiteSpace($Value)) { return $null }

    try { return ConvertTo-TripwireUtc $Value }
    catch { return $null }
}
