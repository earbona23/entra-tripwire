<#
.SYNOPSIS
    Where local state lives: the decoy inventory, the baseline, the licence, captures.

.DESCRIPTION
    XDG on Linux, %APPDATA% on Windows, ~/Library on macOS, overridable with
    $env:ENTRATRIPWIRE_CONFIG_DIR so tests and CI never touch a real profile.

    The decoy inventory is deliberately local rather than derived from the tenant. Two
    reasons, and both are the point of the tool: an inventory kept in the directory would
    be readable by exactly the attacker the decoys are meant to catch, and a decoy whose
    "is this a decoy?" answer lives in the directory can be filtered out of an enumeration
    by anyone who reads the same attribute.
#>
function Get-TripwireStateRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($env:ENTRATRIPWIRE_CONFIG_DIR) { $base = $env:ENTRATRIPWIRE_CONFIG_DIR }
    elseif ($IsWindows) { $base = $env:APPDATA }
    elseif ($IsMacOS) { $base = Join-Path $HOME 'Library/Application Support' }
    else { $base = if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path $HOME '.config' } }

    return Join-Path $base 'EntraTripwire'
}

<#
.SYNOPSIS
    Path to a named state file, creating the directory on demand.
#>
function Get-TripwireStatePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('decoys.json', 'baseline.json', 'license.json')]
        [string] $Name
    )

    $root = Get-TripwireStateRoot
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }
    return Join-Path $root $Name
}

<#
.SYNOPSIS
    Path to a file that ships inside the module, used by DEMO mode.
#>
function Get-TripwireDemoPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Name)

    return Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'Demo') $Name
}

<#
.SYNOPSIS
    Read a JSON state file, returning $null when it does not exist.
.DESCRIPTION
    A malformed state file throws rather than returning an empty object. An empty decoy
    inventory and an unreadable decoy inventory produce identical downstream behaviour --
    zero trips -- and only one of them means "nothing happened".
#>
function Read-TripwireJsonFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try {
        return ($raw | ConvertFrom-Json)
    }
    catch {
        throw "'$Path' exists but is not valid JSON: $($_.Exception.Message). Refusing to continue with an unreadable state file."
    }
}
