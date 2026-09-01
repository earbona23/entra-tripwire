<#
.SYNOPSIS
    Read one key out of a map that may be a hashtable or a JSON-derived PSCustomObject.

.DESCRIPTION
    Baselines are written and read as JSON, so `countries`, `asns` and friends arrive as
    PSCustomObject rather than the hashtable they were built as. Every lookup in the
    scoring engine goes through here so that "the baseline came from disk" and "the
    baseline was built in memory" cannot diverge in behaviour -- a difference that would
    otherwise only show up in production, where nobody is looking at the fixtures.

    Returns $null when the key is absent. Absent is a real answer here: it means the
    tenant has never been seen doing this, which is the whole point of the signal.
#>
function Get-TripwireMapValue {
    [CmdletBinding()]
    param(
        [AllowNull()] $Map,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Key
    )

    if ($null -eq $Map -or [string]::IsNullOrEmpty($Key)) { return $null }

    if ($Map -is [System.Collections.IDictionary]) {
        if ($Map.Contains($Key)) { return $Map[$Key] }
        return $null
    }

    $prop = $Map.PSObject.Properties[$Key]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}
