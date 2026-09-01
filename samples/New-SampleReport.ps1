<#
.SYNOPSIS
    Render the sample report the README links to, from the module's DEMO fixtures.

.DESCRIPTION
    Regenerate it after any change that moves a score, so the picture in the README and the
    behaviour of the code cannot drift apart. No tenant is contacted and no real data is
    involved: the fixtures are synthetic.

.EXAMPLE
    pwsh ./samples/New-SampleReport.ps1
#>
[CmdletBinding()]
param(
    [string] $Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'docs/images/sample-report.html')
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repo 'src/EntraTripwire/EntraTripwire.psd1') -Force

$trips = @(Watch-TripwireActivity -Demo)
$trips | Export-TripwireReport -Path $Path -TenantLabel 'contoso.onmicrosoft.com (synthetic fixtures)' -Demo -Confirm:$false | Out-Null

Write-Host "Wrote $Path from $($trips.Count) demo trips." -ForegroundColor Green
