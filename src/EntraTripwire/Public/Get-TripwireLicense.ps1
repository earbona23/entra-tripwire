<#
.SYNOPSIS
    Show the current licence entitlement.

.DESCRIPTION
    Reports the plan, the unlocked features, and -- when there is no entitlement -- the
    reason, so "Pro is not working" is answerable without support: no licence activated,
    a licence that expired, or a key that does not verify.

.EXAMPLE
    Get-TripwireLicense
#>
function Get-TripwireLicense {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $ent = Get-TripwireEntitlement
    [pscustomobject]@{
        Pro          = $ent.Pro
        Plan         = $ent.Plan
        LicensedTo   = $ent.Sub
        Features     = @($ent.Features)
        Reason       = $ent.Reason
        LicenceFile  = Get-TripwireStatePath -Name 'license.json'
        VerifiedHow  = 'ECDSA P-256, offline. Nothing is sent anywhere.'
    }
}
