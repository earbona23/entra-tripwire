#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The Pro licence layer.

    Verified with an EPHEMERAL P-256 keypair injected as the module's public key, so the
    real signing key is never needed -- and never present -- to exercise the mechanism.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'EntraTripwire'
    Import-Module (Join-Path $script:SourceRoot 'EntraTripwire.psd1') -Force
    $script:Module = Get-Module EntraTripwire
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    $script:Ecdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $script:PubSpki = [Convert]::ToBase64String($script:Ecdsa.ExportSubjectPublicKeyInfo())

    function script:Mint([hashtable] $Payload) {
        $json = ($Payload | ConvertTo-Json -Compress)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $sig = $script:Ecdsa.SignData($bytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
        function b64u([byte[]] $b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        return "TRIPWIRE-$(b64u $bytes).$(b64u $sig)"
    }
}

Describe 'Offline verification (ECDSA P-256)' {

    It 'accepts a properly signed key' {
        $key = script:Mint @{ sub = 'Acme'; plan = 'team'; iat = 1000 }
        $r = & $script:Module { param($k, $pub) Test-TripwireLicenseKey -Key $k -PublicKeySpki $pub -NowUnix 2000 } $key $script:PubSpki
        $r.Valid | Should -BeTrue
        $r.Payload.plan | Should -Be 'team'
    }

    It 'rejects an expired key and says so' {
        $key = script:Mint @{ sub = 'Acme'; plan = 'pro'; iat = 1000; exp = 1500 }
        $r = & $script:Module { param($k, $pub) Test-TripwireLicenseKey -Key $k -PublicKeySpki $pub -NowUnix 2000 } $key $script:PubSpki
        $r.Valid | Should -BeFalse
        $r.Reason | Should -Match 'expired'
    }

    It 'rejects a key signed by a different private key' {
        $other = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $json = (@{ sub = 'x'; plan = 'team'; iat = 1 } | ConvertTo-Json -Compress)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $sig = $other.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
        function b64u([byte[]] $b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        $key = "TRIPWIRE-$(b64u $bytes).$(b64u $sig)"
        $r = & $script:Module { param($k, $pub) Test-TripwireLicenseKey -Key $k -PublicKeySpki $pub } $key $script:PubSpki
        $r.Valid | Should -BeFalse
    }

    It 'rejects a key whose payload was edited after signing' {
        $key = script:Mint @{ sub = 'Acme'; plan = 'pro'; iat = 1000 }
        $parts = $key.Substring('TRIPWIRE-'.Length) -split '\.'
        $tampered = [System.Text.Encoding]::UTF8.GetBytes('{"sub":"Acme","plan":"team","iat":1000}')
        $b64 = [Convert]::ToBase64String($tampered).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $forged = "TRIPWIRE-$b64.$($parts[1])"
        $r = & $script:Module { param($k, $pub) Test-TripwireLicenseKey -Key $k -PublicKeySpki $pub } $forged $script:PubSpki
        $r.Valid | Should -BeFalse
    }

    It 'rejects junk and keys minted for a different product, with a reason' {
        foreach ($junk in @('', 'nope', 'TRIPWIRE-bad', 'M365HYGIENE-a.b', 'TRIPWIRE-!!!.???')) {
            $r = & $script:Module { param($k, $pub) Test-TripwireLicenseKey -Key $k -PublicKeySpki $pub } $junk $script:PubSpki
            $r.Valid | Should -BeFalse
            $r.Reason | Should -Not -BeNullOrEmpty
        }
    }

    It 'the embedded production key rejects an ephemeral key' {
        $key = script:Mint @{ sub = 'x'; plan = 'pro'; iat = 1 }
        $r = & $script:Module { param($k) Test-TripwireLicenseKey -Key $k } $key
        $r.Valid | Should -BeFalse -Because 'the ephemeral key is not the project signing key'
    }

    It 'verifies without touching the network: no HTTP call exists in the licence code' {
        $src = Get-Content -LiteralPath (Join-Path $script:SourceRoot 'Private/License.ps1') -Raw
        $src | Should -Not -Match 'Invoke-RestMethod|Invoke-WebRequest|HttpClient|WebClient'
    }
}

Describe 'Feature gating' {

    BeforeAll {
        # Swap the embedded key for the ephemeral one so a locally minted licence verifies.
        $script:RealPub = & $script:Module { $script:LicensePublicKeySpki }
        . $script:Module { param($p) $script:LicensePublicKeySpki = $p } $script:PubSpki
    }
    AfterAll {
        . $script:Module { param($p) $script:LicensePublicKeySpki = $p } $script:RealPub
        Remove-Item Env:\ENTRATRIPWIRE_LICENSE_KEY -ErrorAction SilentlyContinue
    }
    AfterEach {
        Remove-Item Env:\ENTRATRIPWIRE_LICENSE_KEY -ErrorAction SilentlyContinue
    }

    It 'reports no entitlement, and why, when nothing is activated' {
        $lic = Get-TripwireLicense
        $lic.Pro | Should -BeFalse
        $lic.Reason | Should -Not -BeNullOrEmpty
    }

    It 'unlocks the three Pro features with a valid key' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:Mint @{ sub = 'Acme'; plan = 'pro'; iat = 1 }
        $lic = Get-TripwireLicense
        $lic.Pro | Should -BeTrue
        $lic.Features | Should -Contain 'containment'
        $lic.Features | Should -Contain 'soar'
        $lic.Features | Should -Contain 'multitenant'
    }

    It 'honours a key that licenses only some features' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:Mint @{ sub = 'Acme'; plan = 'pro'; iat = 1; features = @('soar') }
        (& $script:Module { Test-TripwireFeature -Feature 'soar' }) | Should -BeTrue
        (& $script:Module { Test-TripwireFeature -Feature 'containment' }) | Should -BeFalse
    }

    It 'stops honouring an expired key mid-session rather than caching the entitlement' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:Mint @{ sub = 'Acme'; plan = 'pro'; iat = 1; exp = 100 }
        (Get-TripwireLicense).Pro | Should -BeFalse
    }

    It 'refuses a JSONL export without the soar feature, and names the feature' {
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline (New-TestBaseline)
        { $trip | Export-TripwireReport -Format Jsonl -Path (Join-Path ([System.IO.Path]::GetTempPath()) 'x.jsonl') -Confirm:$false } |
            Should -Throw -ExpectedMessage '*soar*'
    }

    It 'allows the JSONL export with the soar feature' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:Mint @{ sub = 'Acme'; plan = 'pro'; iat = 1; features = @('soar') }
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("t-{0}.jsonl" -f [Guid]::NewGuid())
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline (New-TestBaseline)
        $trip | Export-TripwireReport -Format Jsonl -Path $out -Confirm:$false | Out-Null
        Test-Path -LiteralPath $out | Should -BeTrue
        Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
    }

    It 'refuses a named tenant profile without the multitenant feature' {
        { Connect-EntraTripwire -TenantId 'contoso.onmicrosoft.com' -ProfileName 'second' } |
            Should -Throw -ExpectedMessage '*multitenant*'
    }

    It 'keeps the HTML and JSON exports free' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("t-{0}.html" -f [Guid]::NewGuid())
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline (New-TestBaseline)
        $trip | Export-TripwireReport -Format Html -Path $out -Confirm:$false | Out-Null
        Test-Path -LiteralPath $out | Should -BeTrue
        Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
    }
}

<#
    The gate's behaviour on its own error paths.

    A licence gate that throws, or that reads a missing field as "unspecified, so grant
    everything", is a gate that fails in the expensive direction. Every case below was
    measured against the module before these guards existed.
#>
Describe 'The gate fails closed on a malformed licence' {

    BeforeEach {
        $script:RealPub = & $script:Module { $script:LicensePublicKeySpki }
        . $script:Module { param($p) $script:LicensePublicKeySpki = $p } $script:PubSpki
        Remove-Item Env:\ENTRATRIPWIRE_LICENSE_KEY -ErrorAction SilentlyContinue
    }

    AfterEach {
        . $script:Module { param($p) $script:LicensePublicKeySpki = $p } $script:RealPub
        Remove-Item Env:\ENTRATRIPWIRE_LICENSE_KEY -ErrorAction SilentlyContinue
    }

    # [int64]'tomorrow' throws. Get-TripwireLicense raised that conversion error at the
    # caller, and so did Invoke-TripwireContainment, which consults the gate through
    # Test-TripwireFeature -- an unhandled crash in the middle of an incident instead of
    # an answer about licensing.
    It 'reports an unreadable expiry instead of throwing a conversion error' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:Mint @{ sub = 'Acme'; plan = 'pro'; exp = 'tomorrow' }
        { Get-TripwireLicense | Out-Null } | Should -Not -Throw
        $licence = Get-TripwireLicense
        $licence.Pro | Should -BeFalse
        $licence.Reason | Should -Match 'not a whole number of epoch seconds'
    }

    # @() is falsy in PowerShell, so `-and $payload.features` read an explicitly empty
    # feature list as "the field was not set" and handed over all three Pro features.
    It 'treats a licence scoped to no features as entitling nothing, not everything' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:Mint @{ sub = 'Acme'; plan = 'pro'; features = @() }
        $licence = Get-TripwireLicense
        @($licence.Features).Count | Should -Be 0
        (& $script:Module { Test-TripwireFeature -Feature 'containment' }) | Should -BeFalse
    }

    It 'honours a licence scoped to one feature and refuses the others' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:Mint @{ sub = 'Acme'; plan = 'pro'; features = @('soar') }
        (& $script:Module { Test-TripwireFeature -Feature 'soar' }) | Should -BeTrue
        (& $script:Module { Test-TripwireFeature -Feature 'containment' }) | Should -BeFalse
        (& $script:Module { Test-TripwireFeature -Feature 'multitenant' }) | Should -BeFalse
    }

    # The signature proves who minted the key. It proves nothing about the key carrying
    # the fields an entitlement is read from: a signed JSON array granted full Pro to a
    # licensee with no name.
    It 'refuses a signed payload that is not a licence object' {
        $json = '[1,2,3]'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $sig = $script:Ecdsa.SignData($bytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
        function b64u([byte[]] $b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        $env:ENTRATRIPWIRE_LICENSE_KEY = "TRIPWIRE-$(b64u $bytes).$(b64u $sig)"

        $licence = Get-TripwireLicense
        $licence.Pro | Should -BeFalse
        $licence.Reason | Should -Match 'not a licence object'
    }

    It 'refuses a signed payload with no subject' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:Mint @{ plan = 'pro'; iat = 1 }
        (Get-TripwireLicense).Pro | Should -BeFalse
    }

    It 'names an unreadable licence file instead of reporting "no licence activated"' {
        # Get-TripwireStatePath appends an 'EntraTripwire' folder to the config dir.
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("etw-{0}" -f [Guid]::NewGuid())
        New-Item -ItemType Directory -Path (Join-Path $dir 'EntraTripwire') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'EntraTripwire/license.json') -Value '{ this is not json' -Encoding utf8
        $previous = $env:ENTRATRIPWIRE_CONFIG_DIR
        $env:ENTRATRIPWIRE_CONFIG_DIR = $dir
        try {
            $licence = Get-TripwireLicense
            $licence.Pro | Should -BeFalse
            $licence.Reason | Should -Match 'could not be read'
        }
        finally {
            $env:ENTRATRIPWIRE_CONFIG_DIR = $previous
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Not a hypothetical: the module resolves its own private commands inside its own
    # session state, so a same-named function defined by the caller is not consulted.
    # Pinned because it is a property of how the module is loaded, and a future refactor
    # that exported the gate, or moved it to a dot-sourced script, would lose it.
    It 'is not satisfied by a same-named function defined in the caller scope' {
        function Test-TripwireFeature { param($Feature) $true }
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline (New-TestBaseline)
        ($trip | Invoke-TripwireContainment).Licensed | Should -BeFalse
    }
}
