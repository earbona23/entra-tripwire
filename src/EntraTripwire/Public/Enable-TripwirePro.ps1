<#
.SYNOPSIS
    Activate a Pro licence key, or explain what Pro now needs.

.DESCRIPTION
    The paid capabilities are not in this module. They live in a separate module,
    EntraTripwirePro, and holding that module is the entitlement, so for most customers
    there is nothing to activate: install the module and Pro works.

    A licence key is only needed for a time-limited or feature-scoped licence. This
    command hands the key to EntraTripwirePro, which verifies it offline before storing
    it, because the verifier belongs with the code it protects. Without that module
    installed a key cannot be verified and would not unlock anything, so this command
    says so rather than storing something it cannot check.

.PARAMETER LicenseKey
    The key, in the form TRIPWIRE-<payload>.<signature>. Optional: call this command with
    no key to see what the current installation provides.

.EXAMPLE
    Enable-TripwirePro

    Reports whether the paid module is installed and which capabilities it provides.

.EXAMPLE
    Enable-TripwirePro -LicenseKey 'TRIPWIRE-eyJ...abc'

    Verifies the key through EntraTripwirePro and stores it.
#>
function Enable-TripwirePro {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param([string] $LicenseKey)

    if (-not $LicenseKey) { return Get-TripwireLicense }

    if ($PSCmdlet.ShouldProcess('EntraTripwirePro', 'Verify and store the licence key')) {
        $null = Invoke-TripwireProCapability -Capability 'Activate' -Arguments @{ LicenseKey = $LicenseKey }
        $null = Get-TripwireProvider -Refresh
        Write-TripwireLog -Message 'Pro licence activated through EntraTripwirePro.'
    }
    return Get-TripwireLicense
}
