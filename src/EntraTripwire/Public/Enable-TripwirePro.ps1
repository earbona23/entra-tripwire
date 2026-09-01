<#
.SYNOPSIS
    Activate a Pro licence key on this machine.

.DESCRIPTION
    The key is verified locally before it is stored, so an invalid key fails immediately
    and visibly instead of at the moment somebody needs containment to work.

.PARAMETER LicenseKey
    The key, in the form TRIPWIRE-<payload>.<signature>.

.EXAMPLE
    Enable-TripwirePro -LicenseKey 'TRIPWIRE-eyJ...abc'
#>
function Enable-TripwirePro {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $LicenseKey)

    $result = Test-TripwireLicenseKey -Key $LicenseKey
    if (-not $result.Valid) {
        throw "This licence key was not activated: $($result.Reason)"
    }

    $path = Get-TripwireStatePath -Name 'license.json'
    if ($PSCmdlet.ShouldProcess($path, 'Store the verified licence key')) {
        @{ key = $LicenseKey } | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding utf8
        Write-TripwireLog -Message "Pro licence activated for '$($result.Payload.sub)'."
    }
    return Get-TripwireLicense
}
