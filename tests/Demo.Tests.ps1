#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    DEMO mode, end to end, against the fixtures that ship inside the module.

    This is a regression lock on the numbers the README publishes. If a change to the
    engine moves any of them, this file goes red and the README has to be corrected --
    which is the point: a README that documents a score the code no longer produces is a
    lie with a long half-life.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'EntraTripwire'
    Import-Module (Join-Path $script:SourceRoot 'EntraTripwire.psd1') -Force
    $script:Module = Get-Module EntraTripwire
    $script:Trips = @(Watch-TripwireActivity -Demo)
    function script:TripFor([string] $DecoyName, [string] $Source) {
        @($script:Trips | Where-Object { $_.DecoyName -eq $DecoyName -and $_.Touch.source -eq $Source })[0]
    }
}

Describe 'DEMO mode needs no tenant, no credentials and no network' {

    It 'produces the documented number of trips' {
        $script:Trips.Count | Should -Be 9
    }

    It 'never loads the Graph SDK' {
        Get-Module -Name 'Microsoft.Graph.Authentication' | Should -BeNullOrEmpty
    }

    It 'ships six decoys, one of them deliberately contaminated' {
        $decoys = @(Get-TripwireDecoy -Demo)
        $decoys.Count | Should -Be 6
        @($decoys | Where-Object { $_.legitimateUseCount -gt 0 }).Count | Should -Be 1
    }
}

Describe 'The intrusion the fixtures describe' {

    It 'scores the decoy sign-in from an unseen country at 99.6 -- High, and not degraded' {
        $trip = script:TripFor 'svc-backup-archive' 'SignInLog'
        $trip.Confidence | Should -Be 99.6
        $trip.Band | Should -Be 'High'
        $trip.Degraded | Should -BeFalse
        $trip.DistinctDecoys | Should -Be 5
    }

    It 'correlates the sweep: five distinct decoys touched by one actor inside the window' {
        $sweep = @($script:Trips | Where-Object { $_.ActorLabel -eq 'svc-backup-archive@contoso.com' -or $_.ActorLabel -eq 'svc-backup-archive' })
        @($sweep | ForEach-Object { $_.DistinctDecoys } | Sort-Object -Unique) | Should -Be @(5)
    }

    It 'marks the audit-sourced touches degraded, because audits carry no origin' {
        $trip = script:TripFor 'admin.legacy' 'DirectoryAudit'
        $trip.Degraded | Should -BeTrue
        $trip.Withheld | Should -Be @('OriginAnomaly')
        $trip.Confidence | Should -Be 74.6
        $trip.Band | Should -Be 'Medium'
    }

    It 'THE POINT OF THE ENGINE: the same sweep on a contaminated decoy scores Low' {
        # Identical actor, identical minute, identical fan-out. The only difference is that
        # hr-export has 14 recorded legitimate uses, so its purity signal is zero.
        $clean = script:TripFor 'admin.legacy' 'DirectoryAudit'
        $dirty = script:TripFor 'hr-export' 'DirectoryAudit'
        $dirty.DistinctDecoys | Should -Be $clean.DistinctDecoys
        $dirty.Confidence | Should -Be 34.6
        $dirty.Band | Should -Be 'Low'
        # Exactly the DecoyPurity weight x 100. Rounded because the two scores are sums of
        # doubles: the raw difference is 40.000000000000006.
        [Math]::Round(($clean.Confidence - $dirty.Confidence), 1) | Should -Be 40
    }

    It 'fires impossible travel on the dormant admin converted into a decoy' {
        $trip = script:TripFor 'p.morales' 'SignInLog'
        $trip.Confidence | Should -Be 74.6
        $trip.Band | Should -Be 'Medium'
        ($trip.Signals | Where-Object Name -eq 'OriginAnomaly').Rationale | Should -Match 'Impossible travel'
    }

    It 'leaves a lone touch at a normal hour in the Low band' {
        $trip = script:TripFor 'svc-backup-archive' 'DirectoryAudit'
        $trip.Confidence | Should -Be 40.3
        $trip.Band | Should -Be 'Low'
    }
}

Describe 'The two false positives the engine is built to swallow' {

    It 'suppresses the planter provisioning its own decoy' {
        $sup = @($script:Trips | Where-Object { $_.SuppressionReason -match 'provisioning window' })
        $sup.Count | Should -Be 1
        $sup[0].Confidence | Should -Be 0
    }

    It 'suppresses the tenant vulnerability scanner sweeping the directory at 04:00' {
        $sup = @($script:Trips | Where-Object { $_.SuppressionReason -match 'allowlist' })
        $sup.Count | Should -Be 1
        $sup[0].DecoyName | Should -Be 'admin.legacy'
    }

    It 'without those two rules the scanner sweep alone would raise an alert' {
        # Same event, allowlist removed: it stops being suppressed. This is what the rule buys.
        $baseline = Get-TripwireBaseline -Demo
        $baseline.suppressedActors = @()
        $rescored = @(Watch-TripwireActivity -Demo -Baseline $baseline)
        @($rescored | Where-Object { $_.Band -eq 'Suppressed' }).Count | Should -Be 1
    }
}

Describe 'Only one trip in the fixtures is eligible for containment' {

    It 'exactly one High trip, and it is the credential use' {
        $high = @($script:Trips | Where-Object { $_.Band -eq 'High' })
        $high.Count | Should -Be 1
        $high[0].Touch.source | Should -Be 'SignInLog'
    }

    It 'the plan for it is a dry run that touches nothing' {
        $high = @($script:Trips | Where-Object { $_.Band -eq 'High' })[0]
        $result = $high | Invoke-TripwireContainment
        $result.Mode | Should -Be 'DryRun'
        @($result.Performed).Count | Should -Be 0
    }
}
