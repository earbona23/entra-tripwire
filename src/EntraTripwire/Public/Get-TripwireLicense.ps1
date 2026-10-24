<#
.SYNOPSIS
    Show what the paid capabilities of this installation are, and why.

.DESCRIPTION
    Answers "Pro is not working" without support. The paid capabilities live in a separate
    module, EntraTripwirePro, so there are exactly three answers and this command names
    which one applies: the module is not installed, it is installed and provides its
    capabilities, or it is installed and provides none because the licence it holds has
    lapsed or does not verify.

    Every property the previous licence-based version returned is still here, so a script
    that read Pro, Plan, LicensedTo, Features or Reason keeps working.

.EXAMPLE
    Get-TripwireLicense
#>
function Get-TripwireLicense {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $provider = Get-TripwireProvider
    [pscustomobject]@{
        Pro             = $provider.Available
        Plan            = if ($provider.Available) { 'Pro' } else { 'Free' }
        LicensedTo      = $null
        Features        = @($provider.Capabilities)
        Reason          = $provider.Reason
        Provider        = $provider.Name
        ProviderVersion = $provider.Version
        VerifiedHow     = 'The paid capabilities are provided by the EntraTripwirePro module. Holding it is the entitlement; a licence key is only needed for a time-limited or feature-scoped licence, and is verified offline by that module.'
    }
}
