#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The five gates on containment. Each one is tested by holding the other four open.

    A gate that has never been observed refusing something is not a gate, so every test in
    this file asserts BOTH that the action was blocked and that nothing reached Graph.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'EntraTripwire'
    Import-Module (Join-Path $script:SourceRoot 'EntraTripwire.psd1') -Force
    $script:Module = Get-Module EntraTripwire
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Install-GraphStub -Module $script:Module

    $script:Ecdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $script:PubSpki = [Convert]::ToBase64String($script:Ecdsa.ExportSubjectPublicKeyInfo())
    $script:RealPub = & $script:Module { $script:LicensePublicKeySpki }
    . $script:Module { param($p) $script:LicensePublicKeySpki = $p } $script:PubSpki

    function script:MintPro {
        $json = (@{ sub = 'Test'; plan = 'pro'; iat = 1 } | ConvertTo-Json -Compress)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $sig = $script:Ecdsa.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
        function b64u([byte[]] $b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        return "TRIPWIRE-$(b64u $bytes).$(b64u $sig)"
    }

    # A trip that clears every content gate: pristine decoy, unseen origin, four-decoy
    # sweep, dead hour. Every test below starts from this and closes exactly one gate.
    function script:NewHighTrip {
        param([switch] $Degraded)
        $baseline = if ($Degraded) { $null } else { New-TestBaseline }
        $touch = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512' `
            -ActorId 'u-decoy-1' -ActorUpn 'svc-bait@contoso.com'
        Measure-TripwireConfidence -Touch $touch -Decoy (New-TestDecoy) -Baseline $baseline -DistinctDecoyCount 4
    }
}

AfterAll {
    . $script:Module { param($p) $script:LicensePublicKeySpki = $p } $script:RealPub
    Remove-Item Env:\ENTRATRIPWIRE_LICENSE_KEY -ErrorAction SilentlyContinue
}

# Pester does not allow a setup block directly in the container, so every Describe lives
# inside this one and shares its reset.
Describe 'Containment' {

BeforeEach {
    Clear-GraphStubCall -Module $script:Module
    Remove-Item Env:\ENTRATRIPWIRE_LICENSE_KEY -ErrorAction SilentlyContinue
}

Describe 'The plan is free, complete, and changes nothing' {

    It 'defaults to a dry run even with a Pro licence and no other blocker' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:MintPro
        $result = script:NewHighTrip | Invoke-TripwireContainment
        $result.Mode | Should -Be 'DryRun'
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
    }

    It 'names the exact Graph call for every eligible action, so it can be run by hand' {
        $result = script:NewHighTrip | Invoke-TripwireContainment
        $revoke = $result.Plan | Where-Object Name -eq 'RevokeActorSessions'
        $revoke.Eligible | Should -BeTrue
        $revoke.Method | Should -Be 'POST'
        $revoke.Path | Should -Be '/v1.0/users/u-decoy-1/revokeSignInSessions'
    }

    It 'explains why an action is not eligible instead of dropping it silently' {
        $touch = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512' -ActorId '' -Ip '198.51.100.1'
        $trip = Measure-TripwireConfidence -Touch $touch -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) -DistinctDecoyCount 4
        $result = $trip | Invoke-TripwireContainment
        $revoke = $result.Plan | Where-Object Name -eq 'RevokeActorSessions'
        $revoke.Eligible | Should -BeFalse
        $revoke.Why | Should -Match 'no directory object id'
    }
}

Describe 'GATE 1 -- band' {

    It 'refuses a Medium trip and says which band is required' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:MintPro
        # Pristine decoy + unseen country, no fan-out, peak hour: 65, Medium.
        $touch = New-TestTouch -Timestamp '2026-06-15T14:00:00Z' -Country 'KP' -Asn '7922'
        $trip = Measure-TripwireConfidence -Touch $touch -Decoy (New-TestDecoy) -Baseline (New-TestBaseline)
        $trip.Band | Should -Be 'Medium'

        $result = $trip | Invoke-TripwireContainment -Execute -CapturePath (Join-Path ([System.IO.Path]::GetTempPath()) "inc-$([Guid]::NewGuid())") -Confirm:$false
        $result.Mode | Should -Be 'DryRun'
        ($result.Blockers -join ' ') | Should -Match 'High band'
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
    }

    It 'refuses a Suppressed trip' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:MintPro
        $b = New-TestBaseline -SuppressedActors @('actor-1')
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline $b -DistinctDecoyCount 6
        $result = $trip | Invoke-TripwireContainment -Execute -CapturePath (Join-Path ([System.IO.Path]::GetTempPath()) "inc-$([Guid]::NewGuid())") -Confirm:$false
        $result.Mode | Should -Be 'DryRun'
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
    }
}

Describe 'GATE 2 -- degraded scoring' {

    It 'refuses a High trip that was scored with a signal withheld' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:MintPro
        # No baseline: purity 40 + fan-out 25 = 65 with two signals withheld. Even raising
        # fan-out cannot reach High, so build the degraded case explicitly.
        $touch = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512'
        $trip = Measure-TripwireConfidence -Touch $touch -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) -DistinctDecoyCount 4
        $trip.Band | Should -Be 'High'

        # Same trip, marked as it would be had a signal been unavailable.
        $trip.Degraded = $true
        $trip.Withheld = @('OriginAnomaly')

        $result = $trip | Invoke-TripwireContainment -Execute -CapturePath (Join-Path ([System.IO.Path]::GetTempPath()) "inc-$([Guid]::NewGuid())") -Confirm:$false
        $result.Mode | Should -Be 'DryRun'
        ($result.Blockers -join ' ') | Should -Match 'lower bound'
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
    }

    It 'proceeds when the operator explicitly accepts a degraded score' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:MintPro
        $touch = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512' -ActorId 'u-decoy-1'
        $trip = Measure-TripwireConfidence -Touch $touch -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) -DistinctDecoyCount 4
        $trip.Degraded = $true
        $trip.Withheld = @('OriginAnomaly')

        $capture = Join-Path ([System.IO.Path]::GetTempPath()) ("inc-{0}" -f [Guid]::NewGuid())
        $result = $trip | Invoke-TripwireContainment -Execute -AcceptDegraded -CapturePath $capture -Confirm:$false
        $result.Mode | Should -Be 'Executed'
        Remove-Item -LiteralPath $capture -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'GATE 3 -- explicit -Execute' {

    It 'is the only thing standing between a plan and an action' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:MintPro
        $trip = script:NewHighTrip

        ($trip | Invoke-TripwireContainment).Mode | Should -Be 'DryRun'
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0

        $capture = Join-Path ([System.IO.Path]::GetTempPath()) ("inc-{0}" -f [Guid]::NewGuid())
        ($trip | Invoke-TripwireContainment -Execute -CapturePath $capture -Confirm:$false).Mode | Should -Be 'Executed'
        @(Get-GraphStubCall -Module $script:Module).Count | Should -BeGreaterThan 0
        Remove-Item -LiteralPath $capture -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'GATE 4 -- ShouldProcess' {

    It 'performs nothing under -WhatIf' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:MintPro
        $result = script:NewHighTrip | Invoke-TripwireContainment -Execute -CapturePath (Join-Path ([System.IO.Path]::GetTempPath()) "inc-$([Guid]::NewGuid())") -WhatIf
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
        @($result.Performed | Where-Object Status -eq 'Done').Count | Should -Be 0
    }
}

Describe 'GATE 5 -- Pro licence' {

    It 'refuses to execute without the containment feature but hands over the whole plan' {
        $result = script:NewHighTrip | Invoke-TripwireContainment -Execute -CapturePath (Join-Path ([System.IO.Path]::GetTempPath()) "inc-$([Guid]::NewGuid())") -Confirm:$false
        $result.Mode | Should -Be 'DryRun'
        $result.Licensed | Should -BeFalse
        ($result.Blockers -join ' ') | Should -Match 'Pro feature'
        @($result.Plan | Where-Object Eligible).Count | Should -BeGreaterThan 0
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
    }
}

Describe 'What containment actually does when every gate is open' {

    It 'revokes the actor sessions, disables the used decoy, and captures the context' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:MintPro
        $capture = Join-Path ([System.IO.Path]::GetTempPath()) ("inc-{0}" -f [Guid]::NewGuid())
        $result = script:NewHighTrip | Invoke-TripwireContainment -Execute -CapturePath $capture -Confirm:$false

        $calls = Get-GraphStubCall -Module $script:Module
        @($calls | Where-Object { $_.Uri -eq '/v1.0/users/u-decoy-1/revokeSignInSessions' }).Count | Should -Be 1
        @($calls | Where-Object { $_.Method -eq 'PATCH' -and $_.Uri -eq '/v1.0/users/u-decoy-1' }).Count | Should -Be 1
        @($calls | Where-Object { $_.Method -eq 'PATCH' }).Body | Should -Match '"accountEnabled":\s*false'
        (Get-ChildItem -Path $capture -Filter '*.json').Count | Should -Be 1
        @($result.Performed | Where-Object Status -eq 'Done').Count | Should -Be 3

        Remove-Item -LiteralPath $capture -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'does not disable a decoy that was merely READ: that would tell the intruder they were seen' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:MintPro
        $touch = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512' -Source 'DirectoryAudit'
        $trip = Measure-TripwireConfidence -Touch $touch -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) -DistinctDecoyCount 4
        $result = $trip | Invoke-TripwireContainment
        $disable = $result.Plan | Where-Object Name -eq 'DisableDecoy'
        $disable.Eligible | Should -BeFalse
        $disable.Why | Should -Match 'read rather than used'
    }

    It 'honours -Action, so an operator can capture without touching the tenant' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:MintPro
        $capture = Join-Path ([System.IO.Path]::GetTempPath()) ("inc-{0}" -f [Guid]::NewGuid())
        script:NewHighTrip | Invoke-TripwireContainment -Execute -Action CaptureContext -CapturePath $capture -Confirm:$false | Out-Null
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
        (Get-ChildItem -Path $capture -Filter '*.json').Count | Should -Be 1
        Remove-Item -LiteralPath $capture -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'reports a failed action as Failed rather than folding it into a success' {
        $env:ENTRATRIPWIRE_LICENSE_KEY = script:MintPro
        # Make the Graph write throw for this test only.
        . $script:Module { function Invoke-MgGraphRequest { param($Method, $Uri, $Body, $OutputType, $ErrorAction) throw 'Graph said no' } }
        try {
            $capture = Join-Path ([System.IO.Path]::GetTempPath()) ("inc-{0}" -f [Guid]::NewGuid())
            $result = script:NewHighTrip | Invoke-TripwireContainment -Execute -CapturePath $capture -Confirm:$false -WarningAction SilentlyContinue
            @($result.Performed | Where-Object Status -eq 'Failed').Count | Should -BeGreaterThan 0
            Remove-Item -LiteralPath $capture -Recurse -Force -ErrorAction SilentlyContinue
        }
        finally {
            Install-GraphStub -Module $script:Module
        }
    }
}

}
