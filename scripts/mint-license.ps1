<#
.SYNOPSIS
    Mint a signed EntraTripwire Pro licence key. Owner-only: it needs the private signing
    key, which is in .gitignore and never ships with the module.

.EXAMPLE
    ./scripts/mint-license.ps1 -Sub 'Acme Inc' -Plan team -Days 365

.EXAMPLE
    ./scripts/mint-license.ps1 -Sub 'Acme Inc' -Feature soar -Days 365
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Sub,
    [ValidateSet('pro', 'team')][string] $Plan = 'pro',
    [ValidateSet('containment', 'soar', 'multitenant')][string[]] $Feature,
    [int] $Days = 0,
    [string] $SigningKeyPath = './.secrets/license-signing-key.pem'
)

$ecdsa = [System.Security.Cryptography.ECDsa]::Create()
$ecdsa.ImportFromPem((Get-Content -LiteralPath $SigningKeyPath -Raw))

$now = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$payload = [ordered]@{ sub = $Sub; plan = $Plan; iat = $now }
if ($Days -gt 0) { $payload['exp'] = $now + ($Days * 86400) }
if ($Feature) { $payload['features'] = $Feature }

$json = ($payload | ConvertTo-Json -Compress)
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$sig = $ecdsa.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)

function ToB64Url([byte[]] $b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
$key = "TRIPWIRE-$(ToB64Url $bytes).$(ToB64Url $sig)"

$window = if ($Days -gt 0) { ", $Days days" } else { ' (perpetual)' }
Write-Host "Minted $Plan licence for '$Sub'$window" -ForegroundColor Green
Write-Output $key
