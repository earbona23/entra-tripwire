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
