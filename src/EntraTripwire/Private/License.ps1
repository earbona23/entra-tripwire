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

# WHAT THIS GATE IS, AND IS NOT.
#
# It is a correct offline verifier. Nobody can mint a key without the private signing key,
# and every honest failure -- no licence, an expired one, a malformed one, a corrupt licence
# file, an exception during verification -- resolves to NO entitlement with a reason the
# operator can act on. Those paths are the ones that decide whether a paying customer can
# work and whether a non-paying one is quietly let through, and they are covered by tests.
#
# It is NOT tamper-proof against the machine it runs on, and it cannot be. This is an
# MIT-licensed PowerShell module: the source is on disk, the verification key is a variable
# in a dot-sourced script, and anyone who can run code in the session can redefine a
# function inside the module scope. Locking the variable down would buy nothing a text
# editor cannot undo, while breaking the ability to exercise the mechanism in tests with an
# ephemeral key instead of the real one. The gate is an honest answer to an honest question,
# not a DRM scheme, and it is written to be read that way.
#
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

    # The signature proves WHO minted the key. It says nothing about the key carrying the
    # fields the entitlement is read from, and a signed payload that is a JSON array, a
    # number or a string sailed through every check below and granted every Pro feature to
    # nobody in particular. A licence has to identify its licensee.
    if ($payload -isnot [pscustomobject] -or [string]::IsNullOrWhiteSpace([string]$payload.sub)) {
        return fail('The signed payload is not a licence object with a subject.')
    }

    if ($payload.PSObject.Properties.Name -contains 'exp') {
        # [int64] on a value that is not a number THROWS, and this function is called from
        # Invoke-TripwireContainment through Test-TripwireFeature -- so a malformed expiry
        # came out as an unhandled conversion error in the middle of an incident instead of
        # "your licence is malformed". An expiry that cannot be read is not an expiry that
        # has not passed: it fails closed.
        $exp = 0L
        if (-not [int64]::TryParse([string]$payload.exp, [ref] $exp)) {
            return [pscustomobject]@{ Valid = $false; Payload = $payload; Reason = 'The licence expiry is not a whole number of epoch seconds, so it cannot be trusted. Ask for a replacement key.' }
        }
        if ($NowUnix -gt $exp) {
            return [pscustomobject]@{ Valid = $false; Payload = $payload; Reason = 'The licence expired.' }
        }
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

    $denied = { param($reason) [pscustomobject]@{ Pro = $false; Plan = $null; Features = @(); Sub = $null; Reason = $reason } }

    if (-not $Key) { $Key = $env:ENTRATRIPWIRE_LICENSE_KEY }
    if (-not $Key) {
        $path = Get-TripwireStatePath -Name 'license.json'
        if (Test-Path -LiteralPath $path) {
            # A licence file that exists and cannot be read is NOT the same as no licence,
            # and reporting it as one sent the operator to buy a key they already own.
            try { $Key = (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).key }
            catch { return & $denied "The licence file at $path exists but could not be read: $($_.Exception.Message). Re-run Enable-TripwirePro with your key." }
            if (-not $Key) { return & $denied "The licence file at $path has no 'key' property. Re-run Enable-TripwirePro with your key." }
        }
    }
    if (-not $Key) { return & $denied 'No licence activated.' }

    # Nothing below may throw. This is the function Invoke-TripwireContainment consults
    # before it decides whether it is allowed to act, and an exception there would surface
    # as a crash during an incident rather than as a licensing answer.
    try { $r = Test-TripwireLicenseKey -Key $Key }
    catch { return & $denied "The licence could not be verified: $($_.Exception.Message)" }

    if (-not $r.Valid) { return & $denied $r.Reason }

    # Present-but-empty is a real answer: a licence scoped to no features entitles nothing.
    # Treating it as "unspecified, so grant everything" -- which a truthiness test on an
    # empty array does in PowerShell -- is the fail-open direction, and the one that costs.
    $features = if ($r.Payload.PSObject.Properties.Name -contains 'features') {
        @($r.Payload.features | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    }
    else { @($script:ProFeatures) }

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
