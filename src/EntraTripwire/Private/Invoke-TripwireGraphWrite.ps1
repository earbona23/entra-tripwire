<#
.SYNOPSIS
    The one write path to Microsoft Graph, constrained by an explicit allowlist.

.DESCRIPTION
    This module does write to a tenant -- it has to, because planting a decoy creates an
    object and containing an intruder disables one. What it must never do is grow an
    arbitrary write surface, so every write is matched against the allowlist below before
    it is issued, and anything unmatched throws instead of being sent.

    Two properties of the allowlist are worth stating because they are what make automated
    containment safe to hand to a machine:

      * The only PATCH bodies permitted are {"accountEnabled": false}. The gateway can
        disable an identity and is structurally incapable of enabling one. A bug, a bad
        merge or a hostile input cannot turn containment into a privilege grant.
      * There is no allowlist entry that adds a credential, assigns a role, grants consent,
        or writes to any object outside users, applications and service principals.

    tests/Safety.Tests.ps1 asserts both, and asserts that Invoke-MgGraphRequest appears in
    exactly two files in the whole module.
#>

$script:TripwireWriteAllowlist = @(
    @{ Method = 'POST'; Pattern = '^/v1\.0/users$'; Purpose = 'Plant a decoy user' }
    @{ Method = 'POST'; Pattern = '^/v1\.0/applications$'; Purpose = 'Plant a decoy application registration' }
    @{ Method = 'POST'; Pattern = '^/v1\.0/applications/[^/]+/addPassword$'; Purpose = 'Plant a decoy client secret' }
    @{ Method = 'POST'; Pattern = '^/v1\.0/users/[^/]+/revokeSignInSessions$'; Purpose = 'Containment: revoke the actor sessions' }
    @{ Method = 'PATCH'; Pattern = '^/v1\.0/users/[^/]+$'; Purpose = 'Containment: disable an identity'; BodyMustEqual = @{ accountEnabled = $false } }
    @{ Method = 'PATCH'; Pattern = '^/v1\.0/servicePrincipals/[^/]+$'; Purpose = 'Containment: disable a decoy service principal'; BodyMustEqual = @{ accountEnabled = $false } }
    @{ Method = 'DELETE'; Pattern = '^/v1\.0/users/[^/]+$'; Purpose = 'Remove a decoy user' }
    @{ Method = 'DELETE'; Pattern = '^/v1\.0/applications/[^/]+$'; Purpose = 'Remove a decoy application' }
)

<#
.SYNOPSIS
    Match a write against the allowlist. Returns the matching entry, or $null.
.DESCRIPTION
    Separated from the issuing function so tests can interrogate the policy without a
    tenant, a mock, or a network stack.
#>
function Get-TripwireWritePermit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Method,
        [Parameter(Mandatory)] [string] $Path,
        [AllowNull()] $Body
    )

    foreach ($entry in $script:TripwireWriteAllowlist) {
        if ($entry.Method -ne $Method.ToUpperInvariant()) { continue }
        if ($Path -notmatch $entry.Pattern) { continue }

        if ($entry.ContainsKey('BodyMustEqual')) {
            if ($null -eq $Body) { continue }
            $expected = $entry.BodyMustEqual
            $actualKeys = @($Body.Keys | Sort-Object)
            $expectedKeys = @($expected.Keys | Sort-Object)
            if (($actualKeys -join ',') -ne ($expectedKeys -join ',')) { continue }
            $mismatch = $false
            foreach ($k in $expectedKeys) {
                if ([string]$Body[$k] -ne [string]$expected[$k]) { $mismatch = $true; break }
            }
            if ($mismatch) { continue }
        }

        return $entry
    }

    return $null
}

<#
.SYNOPSIS
    Issue an allowlisted write. Refuses anything else.
#>
function Invoke-TripwireGraphWrite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('POST', 'PATCH', 'DELETE')] [string] $Method,
        [Parameter(Mandatory)] [string] $Path,
        [AllowNull()] [hashtable] $Body
    )

    $permit = Get-TripwireWritePermit -Method $Method -Path $Path -Body $Body
    if ($null -eq $permit) {
        throw "EntraTripwire refused a write that is not on its allowlist: $Method $Path. This is a guard, not a transient error -- see Invoke-TripwireGraphWrite."
    }

    Write-TripwireLog -Message "Graph write permitted ($($permit.Purpose)): $Method $Path"

    $params = @{ Method = $Method; Uri = $Path; OutputType = 'PSObject'; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $params['Body'] = ($Body | ConvertTo-Json -Depth 8 -Compress) }

    return Invoke-MgGraphRequest @params
}
