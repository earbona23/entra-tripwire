#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The paid capabilities are not in this repository. These tests are about the only thing
    that is: the question "is the paid module installed, and what does it provide?", and
    the three answers it can give.

    The one that matters most is the third. A module that is installed but entitles
    nothing -- a lapsed or feature-scoped licence -- must read as NOT entitled. Reading it
    as entitled is the direction that costs the author money, and reading an absent module
    as entitled is the direction that lets containment try to act with nothing behind it.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'EntraTripwire'
    Import-Module (Join-Path $script:SourceRoot 'EntraTripwire.psd1') -Force
    $script:Module = Get-Module EntraTripwire
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
}

AfterAll {
    Remove-ProStub -Module $script:Module
}

Describe 'The paid module is absent' {

    BeforeEach { Remove-ProStub -Module $script:Module }

    It 'reports it as unavailable and names it in the reason' {
        $p = & $script:Module { Get-TripwireProvider }
        $p.Available | Should -BeFalse
        $p.Capabilities | Should -BeNullOrEmpty
        $p.Reason | Should -Match 'EntraTripwirePro'
    }

    It 'answers false for every capability without throwing' {
        foreach ($f in @('containment', 'soar', 'multitenant')) {
            & $script:Module { param($x) Test-TripwireProFeature -Feature $x } $f | Should -BeFalse
        }
    }

    It 'refuses a capability call with the reason rather than a null reference' {
        { & $script:Module { Invoke-TripwireProCapability -Capability 'Webhook' -Arguments @{ Uri = 'https://x'; Trip = @{} } } } |
            Should -Throw -ExpectedMessage '*EntraTripwirePro*'
    }

    It 'reports Free from Get-TripwireLicense, keeping every property the licence version returned' {
        $l = Get-TripwireLicense
        $l.Pro | Should -BeFalse
        $l.Plan | Should -Be 'Free'
        $l.Features | Should -BeNullOrEmpty
        $l.Reason | Should -Match 'not installed'
        foreach ($prop in @('Pro', 'Plan', 'LicensedTo', 'Features', 'Reason')) {
            $l.PSObject.Properties.Name | Should -Contain $prop
        }
    }

    It 'does not store a licence key it cannot verify' {
        # The verifier went with the capabilities. Storing an unchecked key here would be
        # the silent failure the original design existed to avoid: the key would look
        # activated and nothing would work.
        { Enable-TripwirePro -LicenseKey 'TRIPWIRE-not.a.real.key' -Confirm:$false } |
            Should -Throw -ExpectedMessage '*EntraTripwirePro*'
    }

    It 'reports status instead of failing when called with no key at all' {
        (Enable-TripwirePro).Pro | Should -BeFalse
    }
}

Describe 'The paid module is present' {

    It 'reports every capability it advertises' {
        Install-ProStub -Module $script:Module
        $p = & $script:Module { Get-TripwireProvider }
        $p.Available | Should -BeTrue
        $p.Capabilities | Should -Contain 'containment'
        (Get-TripwireLicense).Plan | Should -Be 'Pro'
    }

    It 'scopes capabilities to what it advertises and not to the full set' {
        Install-ProStub -Module $script:Module -Capabilities @('soar')
        & $script:Module { Test-TripwireProFeature -Feature 'soar' } | Should -BeTrue
        & $script:Module { Test-TripwireProFeature -Feature 'containment' } | Should -BeFalse
        & $script:Module { Test-TripwireProFeature -Feature 'multitenant' } | Should -BeFalse
    }
}

Describe 'Discovery itself, with the stub out of the way' {

    # The stub used above sets the resolved provider directly, which is what makes the gate
    # tests fast and isolated -- and it means those tests never execute Get-TripwireProvider
    # itself. A surviving mutant said so. These two go through the real discovery path with
    # the module lookup mocked instead.

    BeforeEach {
        Remove-ProStub -Module $script:Module
        & $script:Module { $script:TripwireProvider = $null }
    }

    AfterEach { Remove-ProStub -Module $script:Module }

    It 'reports available only when the module advertises at least one capability' -ForEach @(
        @{ Caps = @('containment', 'soar'); Expected = $true }
        @{ Caps = @(); Expected = $false }
    ) {
        $script:FakeCaps = $Caps
        & $script:Module {
            param($caps)
            # One unfiltered mock: the resolver asks Get-Module twice, once with
            # -ListAvailable to find it and once without to read its version.
            Mock Get-Module -ModuleName EntraTripwire { [pscustomobject]@{ Name = 'EntraTripwirePro'; Version = [version]'1.0.0' } }
            Mock Import-Module -ModuleName EntraTripwire {}
            Mock Get-Command -ModuleName EntraTripwire { { } }
            # Bound to a module-scope variable, not captured from this param block. A
            # function that closes over an out-of-scope variable returns $null, and
            # @($null).Count is 1 in PowerShell, so the empty case would have read as one
            # capability and the test would have measured nothing.
            $script:FakeCaps = @($caps)
            function script:Get-EntraTripwireProCapability { return $script:FakeCaps }
        } $Caps

        # Measured through the real resolver, not through the cache the stub writes.
        $p = & $script:Module { Get-TripwireProvider -Refresh }
        $p.Available | Should -Be $Expected
        if (-not $Expected) {
            $p.Reason | Should -Match 'no capabilities' -Because 'an installed module that entitles nothing must say so'
        }
    }
}

Describe 'The paid module is present but entitles nothing' {

    It 'reads as not entitled, and says the module is installed' {
        Install-ProStub -Module $script:Module -Capabilities @()
        $p = & $script:Module { Get-TripwireProvider }
        $p.Available | Should -BeFalse
        $p.Reason | Should -Match 'installed'
        & $script:Module { Test-TripwireProFeature -Feature 'containment' } | Should -BeFalse
    }
}
