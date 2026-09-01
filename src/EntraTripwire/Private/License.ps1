<#
.SYNOPSIS
    Offline verification of an EntraTripwire Pro licence, and the entitlement the rest of
    the module reads.

.DESCRIPTION
    Everything that DETECTS is free: planting decoys, collecting touches, the whole
    confidence engine, the HTML report. Pro unlocks the parts that ACT or scale --
    executing containment, emitting to a SOAR/SIEM pipeline, and running more than one
    tenant profile.

    The licence is an ECDSA P-256 token verified entirely offline against a public key
    embedded below. No account, no callback, no telemetry: a detection tool that phones
    home during an incident is a detection tool that leaks the incident.

    A key is  TRIPWIRE-<base64url(payloadJson)>.<base64url(DER-signature)>.

    Ed25519 has no native verifier in .NET; P-256 is verified by
    System.Security.Cryptography.ECDsa with no third-party dependency, which keeps the
    module installable with nothing but PowerShell 7.
#>

# Embedded verification public key (SubjectPublicKeyInfo, base64). Public by design: it can
# verify a signature and can never mint one. The signing key stays with the project owner.
$script:LicensePublicKeySpki = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHuoPb6Um/DahcfIjvehd4WtL/At7LWdqquUeWLZTN9EFUcN7A/HMkWa5ZAhwGEF8LvTXYSOABj66A8zXfPrDcw=='

$script:LicenseKeyPrefix = 'TRIPWIRE-'
$script:ProFeatures = @('containment', 'soar', 'multitenant')

<#
.SYNOPSIS
    Decode a base64url string to bytes.
#>
function ConvertFrom-TripwireBase64Url {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)] [string] $Text)

    $s = $Text.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [Convert]::FromBase64String($s)
}

<#
.SYNOPSIS
    Verify a licence key offline. Returns an object with Valid, Payload and Reason.
.PARAMETER Key
    The licence key string.
.PARAMETER PublicKeySpki
    Override the embedded key (base64 SPKI). For tests, so the real signing key is never
    needed to exercise the mechanism.
.PARAMETER NowUnix
    Current time as epoch seconds, for deterministic expiry tests.
#>
function Test-TripwireLicenseKey {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Key,
        [string] $PublicKeySpki = $script:LicensePublicKeySpki,
        [int64] $NowUnix = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    )

    function fail($reason) { [pscustomobject]@{ Valid = $false; Payload = $null; Reason = $reason } }

    if ([string]::IsNullOrWhiteSpace($Key) -or -not $Key.StartsWith($script:LicenseKeyPrefix)) {
        return fail('The key is not an EntraTripwire licence key.')
    }
    $body = $Key.Substring($script:LicenseKeyPrefix.Length)
    $dot = $body.IndexOf('.')
    if ($dot -lt 1) { return fail('The key is malformed (missing signature).') }

    try {
        $payloadBytes = ConvertFrom-TripwireBase64Url -Text $body.Substring(0, $dot)
        $signature = ConvertFrom-TripwireBase64Url -Text $body.Substring($dot + 1)
    }
    catch {
        return fail('The key is not valid base64url.')
    }

    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $ecdsa.ImportSubjectPublicKeyInfo([Convert]::FromBase64String($PublicKeySpki), [ref] 0)
    }
    catch {
        return fail('The embedded public key could not be loaded.')
    }

    $ok = $false
    try {
        $ok = $ecdsa.VerifyData(
            $payloadBytes, $signature,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
    }
    catch { $ok = $false }

    if (-not $ok) { return fail('The signature does not verify. This key was not issued for EntraTripwire.') }

    try {
        $payload = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json
    }
    catch {
        return fail('The signed payload is not valid JSON.')
    }

    if ($payload.PSObject.Properties.Name -contains 'exp' -and $NowUnix -gt [int64]$payload.exp) {
        return [pscustomobject]@{ Valid = $false; Payload = $payload; Reason = 'The licence expired.' }
    }

    return [pscustomobject]@{ Valid = $true; Payload = $payload; Reason = $null }
}

<#
.SYNOPSIS
    The current entitlement, re-verified from disk (or $env:ENTRATRIPWIRE_LICENSE_KEY) on
    every call.
.DESCRIPTION
    Re-verified rather than cached at import: a licence that expires mid-session stops
    working in that session, and a test that activates a licence cannot leak entitlement
    into the next test.
#>
function Get-TripwireEntitlement {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowNull()] [string] $Key)

    if (-not $Key) { $Key = $env:ENTRATRIPWIRE_LICENSE_KEY }
    if (-not $Key) {
        $path = Get-TripwireStatePath -Name 'license.json'
        if (Test-Path -LiteralPath $path) {
            try { $Key = (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).key } catch { $Key = $null }
        }
    }
    if (-not $Key) {
        return [pscustomobject]@{ Pro = $false; Plan = $null; Features = @(); Sub = $null; Reason = 'No licence activated.' }
    }

    $r = Test-TripwireLicenseKey -Key $Key
    if (-not $r.Valid) {
        return [pscustomobject]@{ Pro = $false; Plan = $null; Features = @(); Sub = $null; Reason = $r.Reason }
    }

    $features = if ($r.Payload.PSObject.Properties.Name -contains 'features' -and $r.Payload.features) {
        @($r.Payload.features)
    }
    else { $script:ProFeatures }

    [pscustomobject]@{ Pro = $true; Plan = $r.Payload.plan; Features = $features; Sub = $r.Payload.sub; Reason = $null }
}

<#
.SYNOPSIS
    Does the current entitlement include a named Pro feature?
#>
function Test-TripwireFeature {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Feature)

    $ent = Get-TripwireEntitlement
    if (-not $ent.Pro) { return $false }
    return (@($ent.Features) -contains $Feature)
}
