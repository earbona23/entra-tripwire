#Requires -Version 7.2

<#
    EntraTripwire -- deception-based intrusion detection for Microsoft Entra ID.

    Loader. Files are dot-sourced private-first, then the public surface. Only the
    functions in Public/ are exported; everything else stays internal so the module's
    contract is the documented command set rather than whatever happens to be defined.
#>

# Version 1.0 on purpose, not Latest. Microsoft Graph omits optional properties instead
# of returning null -- signInActivity on an unlicensed tenant, location on a sign-in from
# a private range, @odata.nextLink on a final page. StrictMode 2.0+ turns "Graph did not
# return this field" into a terminating error, which is exactly the wrong failure for a
# detector: it converts missing evidence into a crash instead of a withheld signal.
Set-StrictMode -Version 1.0

foreach ($folder in @('Private', 'Public')) {
    $path = Join-Path -Path $PSScriptRoot -ChildPath $folder
    if (-not (Test-Path -LiteralPath $path)) { continue }

    foreach ($file in (Get-ChildItem -Path $path -Filter '*.ps1' -File | Sort-Object Name)) {
        try {
            . $file.FullName
        }
        catch {
            throw "Failed to load '$($file.FullName)': $($_.Exception.Message)"
        }
    }
}

# Declared before anything can read it. StrictMode turns a read of an unset variable into
# a terminating error, so a module-scope variable that is only ever assigned by
# Connect-EntraTripwire would make every command that consults the session crash in a
# session that has not connected -- which is exactly the DEMO-mode path this module
# promises works with no tenant.
$script:TripwireSession = $null

# Remembers which policy object has already passed Assert-TripwirePolicy, so scoring a
# large batch validates once rather than once per touch. Declared here for the same
# StrictMode reason as the session above.
$script:TripwireValidatedPolicy = $null

# The paid module's state, resolved once per session by Get-TripwireProvider. Declared
# here for the same StrictMode reason as the two above: Test-TripwireProFeature reads it
# before anything has had a chance to assign it.
$script:TripwireProvider = $null

# Set by Connect-EntraTripwire when a named tenant profile is in use, so each tenant's
# decoy inventory and baseline stay apart. Null means the shared root, which is where a
# single-tenant installation keeps its files and where they stay.
$script:TripwireStateRootOverride = $null

$publicPath = Join-Path -Path $PSScriptRoot -ChildPath 'Public'
$publicFunctions = @(
    Get-ChildItem -Path $publicPath -Filter '*.ps1' -File -ErrorAction SilentlyContinue |
        ForEach-Object { $_.BaseName }
)

Export-ModuleMember -Function $publicFunctions
