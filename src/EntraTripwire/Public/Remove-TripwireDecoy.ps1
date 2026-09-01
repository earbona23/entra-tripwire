<#
.SYNOPSIS
    Remove a decoy from the tenant and from the inventory.

.DESCRIPTION
    Refuses any object id that is not already in the local inventory. This is the guard
    that keeps a deception tool from becoming a deletion tool: the only objects it can
    delete are ones it recorded itself as bait, so a typo, a copied guid or a hostile
    inventory edit cannot turn into a deleted employee.

.PARAMETER Id
    The decoy id from Get-TripwireDecoy.

.PARAMETER KeepObject
    Drop the decoy from the inventory without deleting anything in the tenant.

.EXAMPLE
    Remove-TripwireDecoy -Id decoy-8f21ab3c9d40 -WhatIf
#>
function Remove-TripwireDecoy {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [switch] $KeepObject,
        [string] $Path
    )

    if (-not $Path) { $Path = Get-TripwireStatePath -Name 'decoys.json' }

    $all = @(Get-TripwireDecoy -Path $Path)
    $target = @($all | Where-Object { [string]$_.id -eq $Id })
    if ($target.Count -eq 0) {
        throw "'$Id' is not in the decoy inventory at $Path. EntraTripwire will only delete objects it recorded as decoys."
    }
    $decoy = $target[0]

    if (-not $KeepObject -and -not [string]::IsNullOrWhiteSpace([string]$decoy.objectId)) {
        # Deliberately NOT named $path: PowerShell variables are case-insensitive, so that
        # would silently overwrite the $Path parameter and write the inventory to a Graph URL.
        $graphPath = if ($decoy.type -eq 'User') { "/v1.0/users/$($decoy.objectId)" } else { "/v1.0/applications/$($decoy.objectId)" }
        if ($PSCmdlet.ShouldProcess("$($decoy.type) '$($decoy.displayName)' ($($decoy.objectId))", 'Delete the decoy object from the tenant')) {
            Invoke-TripwireGraphWrite -Method DELETE -Path $graphPath | Out-Null
        }
    }

    $remaining = @($all | Where-Object { [string]$_.id -ne $Id })
    if ($PSCmdlet.ShouldProcess($Path, "Remove decoy $Id from the inventory")) {
        @{ version = 1; decoys = $remaining } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding utf8
    }

    return $decoy
}
