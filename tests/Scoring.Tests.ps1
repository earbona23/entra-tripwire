#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The false-positive suppression engine.

    These tests are written to fail if the calibration changes, not merely if the code
    crashes: they assert the specific numbers the README and docs/scoring.md publish, and
    the two structural invariants that make automated containment defensible.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'EntraTripwire'
    Import-Module (Join-Path $script:SourceRoot 'EntraTripwire.psd1') -Force
    $script:Module = Get-Module EntraTripwire
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Policy = Get-TripwirePolicy
}

Describe 'Policy shape' {

    It 'the weights sum to exactly 1.00, so confidence is a percentage of obtainable evidence' {
        $w = $script:Policy.Weights
        $sum = $w.DecoyPurity + $w.OriginAnomaly + $w.CrossDecoyFanOut + $w.OffHours
        [Math]::Round($sum, 6) | Should -Be 1.0
    }

    It 'publishes the documented thresholds' {
        $script:Policy.Threshold.High | Should -Be 75
        $script:Policy.Threshold.Medium | Should -Be 45
    }

    It 'accepts an override without losing the untouched keys' {
        $p = Get-TripwirePolicy -Override @{ ImpossibleTravelKph = 1200 }
        $p.ImpossibleTravelKph | Should -Be 1200
        $p.Threshold.High | Should -Be 75
    }
}

Describe 'The signal contract' {

    # New-TripwireSignal is where "unavailable contributes zero" is actually enforced. Every
    # caller today happens to pass Raw = 0 alongside Available = $false, so a defect here is
    # invisible from the outside -- which is exactly why it is tested from the inside.
    It 'an unavailable signal contributes zero however strong its raw value' {
        $s = & $script:Module { New-TripwireSignal -Name 'x' -Weight 0.5 -Raw 0.9 -Available $false }
        $s.Weighted | Should -Be 0
        $s.Raw | Should -Be 0
        $s.Available | Should -BeFalse
    }

    It 'an available signal contributes raw x weight' {
        $s = & $script:Module { New-TripwireSignal -Name 'x' -Weight 0.5 -Raw 0.9 }
        $s.Weighted | Should -Be 0.45
    }

    It 'clamps a raw value outside 0..1 instead of letting it distort the total' {
        $hi = & $script:Module { New-TripwireSignal -Name 'x' -Weight 1.0 -Raw 4.2 }
        $lo = & $script:Module { New-TripwireSignal -Name 'x' -Weight 1.0 -Raw -3 }
        $hi.Raw | Should -Be 1
        $lo.Raw | Should -Be 0
    }
}

Describe 'INVARIANT: no single signal can reach the containment band alone' {

    # This is the property that makes 'High' mean corroborated rather than merely loud.
    It 'the largest single weight is below the High threshold' {
        $w = $script:Policy.Weights
        $largest = @($w.DecoyPurity, $w.OriginAnomaly, $w.CrossDecoyFanOut, $w.OffHours |
                Measure-Object -Maximum).Maximum
        ($largest * 100) | Should -BeLessThan $script:Policy.Threshold.High
    }

    It 'a pristine decoy touched once, from a normal origin, at the busiest hour, scores Low' {
        $baseline = New-TestBaseline
        # 14:00 UTC is the peak hour in the fixture, US/AS7922 is the tenant norm.
        $t = New-TestTouch -Timestamp '2026-06-15T14:00:00Z' -Country 'US' -Asn '7922'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline $baseline -Policy $script:Policy
        $trip.Confidence | Should -Be 40
        $trip.Band | Should -Be 'Low'
        $trip.Degraded | Should -BeFalse
    }
}

Describe 'INVARIANT: a contaminated decoy can never reach the containment band' {

    It 'every other signal at maximum still lands below High when purity is zero' {
        $baseline = New-TestBaseline
        # Purity 0 (11 legitimate uses), unseen country, four decoys, dead hour.
        $decoy = New-TestDecoy -LegitimateUseCount 11
        $t = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '999999'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy $decoy -Baseline $baseline `
            -DistinctDecoyCount 9 -Policy $script:Policy

        $trip.Confidence | Should -BeLessThan $script:Policy.Threshold.High
        $trip.Band | Should -Not -Be 'High'
        ($trip.Signals | Where-Object Name -eq 'DecoyPurity').Raw | Should -Be 0
    }
}

Describe 'Signal (a) decoy purity' {

    It 'a never-used decoy scores the full weight' {
        $s = & $script:Module { param($d, $p) Measure-TripwireDecoyPuritySignal -Decoy $d -Policy $p } (New-TestDecoy) $script:Policy
        $s.Raw | Should -Be 1.0
        $s.Weighted | Should -Be 0.4
        $s.Available | Should -BeTrue
    }

    It 'decays across the documented tiers' {
        foreach ($case in @(@{ Uses = 0; Raw = 1.0 }, @{ Uses = 2; Raw = 0.5 }, @{ Uses = 7; Raw = 0.2 }, @{ Uses = 40; Raw = 0.0 })) {
            $d = New-TestDecoy -LegitimateUseCount $case.Uses
            $s = & $script:Module { param($dd, $p) Measure-TripwireDecoyPuritySignal -Decoy $dd -Policy $p } $d $script:Policy
            $s.Raw | Should -Be $case.Raw -Because "$($case.Uses) legitimate uses should score $($case.Raw)"
        }
    }

    It 'withholds itself when the touched object is not in the inventory' {
        $s = & $script:Module { param($p) Measure-TripwireDecoyPuritySignal -Decoy $null -Policy $p } $script:Policy
        $s.Available | Should -BeFalse
        $s.Weighted | Should -Be 0
    }
}

Describe 'Signal (b) origin anomaly' {

    It 'scores an unseen country at full strength' {
        $s = & $script:Module { param($t, $b, $p) Measure-TripwireOriginSignal -Touch $t -Baseline $b -Policy $p } `
        (New-TestTouch -Country 'KP' -Asn '7922') (New-TestBaseline) $script:Policy
        $s.Raw | Should -Be 1.0
        $s.Rationale | Should -Match 'never appeared'
    }

    It 'scores a rare country below an unseen one' {
        $b = New-TestBaseline -Countries @{ US = 990; ES = 1 }
        $s = & $script:Module { param($t, $bb, $p) Measure-TripwireOriginSignal -Touch $t -Baseline $bb -Policy $p } `
        (New-TestTouch -Country 'ES' -Asn '7922') $b $script:Policy
        $s.Raw | Should -Be 0.6
    }

    It 'scores an unseen autonomous system below an unseen country' {
        $s = & $script:Module { param($t, $b, $p) Measure-TripwireOriginSignal -Touch $t -Baseline $b -Policy $p } `
        (New-TestTouch -Country 'US' -Asn '64512') (New-TestBaseline) $script:Policy
        $s.Raw | Should -Be 0.8
    }

    It 'says a normal origin is normal' {
        $s = & $script:Module { param($t, $b, $p) Measure-TripwireOriginSignal -Touch $t -Baseline $b -Policy $p } `
        (New-TestTouch -Country 'US' -Asn '7922') (New-TestBaseline) $script:Policy
        $s.Raw | Should -Be 0
        $s.Available | Should -BeTrue
    }

    It 'WITHHOLDS itself with no baseline instead of calling an unknown origin normal' {
        $s = & $script:Module { param($t, $p) Measure-TripwireOriginSignal -Touch $t -Baseline $null -Policy $p } `
        (New-TestTouch) $script:Policy
        $s.Available | Should -BeFalse
        $s.Weighted | Should -Be 0
        $s.Rationale | Should -Match 'baseline'
    }

    It 'WITHHOLDS itself when the log source carries no country and no ASN' {
        $s = & $script:Module { param($t, $b, $p) Measure-TripwireOriginSignal -Touch $t -Baseline $b -Policy $p } `
        (New-TestTouch -Country $null -Asn $null -Source 'DirectoryAudit') (New-TestBaseline) $script:Policy
        $s.Available | Should -BeFalse
    }

    It 'fires impossible travel over the tenant norm and says by how much' {
        # New York 01:00 -> Frankfurt 03:20 is about 6,200 km in 2.33 h.
        $b = New-TestBaseline -ActorLastSeen @{
            'actor-1' = @{ timestamp = '2026-06-15T01:00:00Z'; country = 'US'; latitude = 40.7128; longitude = -74.0060 }
        }
        $t = New-TestTouch -Timestamp '2026-06-15T03:20:00Z' -Country 'US' -Asn '7922' -Latitude 50.1109 -Longitude 8.6821
        $s = & $script:Module { param($tt, $bb, $p) Measure-TripwireOriginSignal -Touch $tt -Baseline $bb -Policy $p } $t $b $script:Policy
        $s.Raw | Should -Be 1.0
        $s.Rationale | Should -Match 'Impossible travel'
    }

    It 'does not fire impossible travel on a journey a person could make' {
        # New York 01:00 -> Boston 03:20: ~306 km in 2.33 h, about 130 km/h.
        $b = New-TestBaseline -ActorLastSeen @{
            'actor-1' = @{ timestamp = '2026-06-15T01:00:00Z'; country = 'US'; latitude = 40.7128; longitude = -74.0060 }
        }
        $t = New-TestTouch -Timestamp '2026-06-15T03:20:00Z' -Country 'US' -Asn '7922' -Latitude 42.3601 -Longitude -71.0589
        $s = & $script:Module { param($tt, $bb, $p) Measure-TripwireOriginSignal -Touch $tt -Baseline $bb -Policy $p } $t $b $script:Policy
        $s.Raw | Should -Be 0
    }
}

Describe 'Signal (c) cross-decoy fan-out' {

    It 'gives one decoy no fan-out credit at all' {
        $s = & $script:Module { param($p) Measure-TripwireFanOutSignal -DistinctDecoyCount 1 -Policy $p } $script:Policy
        $s.Raw | Should -Be 0
    }

    It 'climbs across the documented tiers' {
        foreach ($case in @(@{ N = 2; Raw = 0.60 }, @{ N = 3; Raw = 0.85 }, @{ N = 4; Raw = 1.00 }, @{ N = 12; Raw = 1.00 })) {
            $s = & $script:Module { param($n, $p) Measure-TripwireFanOutSignal -DistinctDecoyCount $n -Policy $p } $case.N $script:Policy
            $s.Raw | Should -Be $case.Raw -Because "$($case.N) distinct decoys should score $($case.Raw)"
        }
    }
}

Describe 'Signal (d) off hours' {

    It 'scores the tenant busiest hour at zero' {
        $s = & $script:Module { param($t, $b, $p) Measure-TripwireOffHoursSignal -Touch $t -Baseline $b -Policy $p } `
        (New-TestTouch -Timestamp '2026-06-15T14:00:00Z') (New-TestBaseline) $script:Policy
        $s.Raw | Should -Be 0
    }

    It 'scores a near-dead hour near maximum' {
        $s = & $script:Module { param($t, $b, $p) Measure-TripwireOffHoursSignal -Touch $t -Baseline $b -Policy $p } `
        (New-TestTouch -Timestamp '2026-06-15T03:00:00Z') (New-TestBaseline) $script:Policy
        $s.Raw | Should -BeGreaterThan 0.98
    }

    It 'judges against THIS tenant, not against assumed office hours' {
        # A night-shift tenant: 03:00 is its peak, 14:00 is its dead hour.
        $night = @(90, 95, 98, 100, 96, 90, 60, 30, 10, 5, 3, 2, 2, 1, 1, 2, 5, 15, 40, 70, 85, 90, 92, 94)
        $b = New-TestBaseline -Hours $night
        $atThree = & $script:Module { param($t, $bb, $p) Measure-TripwireOffHoursSignal -Touch $t -Baseline $bb -Policy $p } `
        (New-TestTouch -Timestamp '2026-06-15T03:00:00Z') $b $script:Policy
        $atTwo = & $script:Module { param($t, $bb, $p) Measure-TripwireOffHoursSignal -Touch $t -Baseline $bb -Policy $p } `
        (New-TestTouch -Timestamp '2026-06-15T14:00:00Z') $b $script:Policy
        $atThree.Raw | Should -Be 0
        $atTwo.Raw | Should -BeGreaterThan 0.98
    }

    It 'WITHHOLDS itself when the histogram is missing or the wrong length' {
        foreach ($bad in @($null, (New-TestBaseline -Hours @(1, 2, 3)))) {
            $s = & $script:Module { param($t, $b, $p) Measure-TripwireOffHoursSignal -Touch $t -Baseline $b -Policy $p } `
            (New-TestTouch) $bad $script:Policy
            $s.Available | Should -BeFalse
        }
    }
}

Describe 'Baseline freshness' {

    <#
        Get-TripwireBaseline has always written generatedAt and nothing read it. A baseline
        from six months ago was used in silence, so "unusual country" and "outside working
        hours" were scored against a tenant that had since hired, moved and changed its
        egress. Both of those signals are exactly as meaningful as the history behind them.
    #>

    It 'WITHHOLDS origin and off-hours against a baseline older than the stale age' {
        $old = New-TestBaseline
        $old.generatedAt = '2026-01-01T00:00:00Z'
        $t = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline $old `
            -DistinctDecoyCount 4 -Policy $script:Policy -WarningAction SilentlyContinue

        $trip.Withheld | Should -Contain 'OriginAnomaly'
        $trip.Withheld | Should -Contain 'OffHours'
        $trip.Degraded | Should -BeTrue
        ($trip.Signals | Where-Object Name -eq 'OriginAnomaly').Rationale | Should -Match 'day\(s\) earlier'
    }

    # The direction matters. A stale baseline must make the engine less certain, never more:
    # the withheld signals contribute zero and the weights are not renormalised.
    It 'a stale baseline can only LOWER the score, never raise it' {
        $t = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512'
        $fresh = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) `
            -DistinctDecoyCount 4 -Policy $script:Policy
        $old = New-TestBaseline
        $old.generatedAt = '2025-01-01T00:00:00Z'
        $stale = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline $old `
            -DistinctDecoyCount 4 -Policy $script:Policy
        $stale.Confidence | Should -BeLessThan $fresh.Confidence
        $stale.Confidence | Should -Be 65
    }

    # Age is measured against the TOUCH, not the clock. Re-analysing last month's logs must
    # compare them with the baseline that was current for them, and a baseline built AFTER
    # the event covers the period the event came from, so it is not stale at all.
    It 'measures age against the touch rather than the clock' {
        $b = New-TestBaseline
        $b.generatedAt = '2026-06-14T00:00:00Z'
        $t = New-TestTouch -Timestamp '2026-06-15T14:00:00Z' -Country 'KP' -Asn '7922'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline $b -Policy $script:Policy
        $trip.Withheld | Should -Not -Contain 'OriginAnomaly'
        $trip.Confidence | Should -Be 65
    }

    It 'does not call a baseline built after the touch stale' {
        $b = New-TestBaseline
        $b.generatedAt = '2026-09-01T00:00:00Z'
        $t = New-TestTouch -Timestamp '2026-06-15T14:00:00Z' -Country 'KP' -Asn '7922'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline $b -Policy $script:Policy
        $trip.Withheld | Should -Not -Contain 'OriginAnomaly'
        $trip.Withheld | Should -Not -Contain 'OffHours'
    }

    It 'the stale age is a limit to EXCEED: exactly the limit is still used' {
        $b = New-TestBaseline
        $b.generatedAt = '2026-05-16T14:00:00Z'   # exactly 30 days before the touch
        $t = New-TestTouch -Timestamp '2026-06-15T14:00:00Z' -Country 'KP' -Asn '7922'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline $b `
            -Policy $script:Policy -WarningAction SilentlyContinue
        $trip.Withheld | Should -Not -Contain 'OriginAnomaly'
    }

    # An age nobody can establish is not freshness. Same rule the purity signal applies to
    # an unreadable legitimateUseCount, and the opposite of what PowerShell does for free.
    It 'WITHHOLDS rather than assuming fresh when generatedAt cannot be read' {
        foreach ($stamp in @($null, '', 'last Tuesday', '2026-13-45T99:99:99Z')) {
            $b = New-TestBaseline
            $b.generatedAt = $stamp
            $t = New-TestTouch -Timestamp '2026-06-15T14:00:00Z' -Country 'KP' -Asn '7922'
            $trip = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline $b `
                -Policy $script:Policy -WarningAction SilentlyContinue
            $trip.Withheld | Should -Contain 'OriginAnomaly' -Because "generatedAt '$stamp' establishes no age"
            $trip.Withheld | Should -Contain 'OffHours' -Because "generatedAt '$stamp' establishes no age"
        }
    }

    # `145 -gt $null` is $true and `-not $null` is $true, so a policy that lost a freshness
    # limit would answer this question by accident, in whichever direction the comparison
    # happened to be typed. It is answered by refusing to guess.
    It 'WITHHOLDS when the policy carries no usable freshness limits' {
        $p = Get-TripwirePolicy -Override @{ BaselineStaleAgeDays = 'soon' }
        $t = New-TestTouch -Timestamp '2026-06-15T14:00:00Z' -Country 'KP' -Asn '7922'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) `
            -Policy $p -WarningAction SilentlyContinue
        $trip.Withheld | Should -Contain 'OriginAnomaly'
        ($trip.Signals | Where-Object Name -eq 'OriginAnomaly').Rationale | Should -Match 'BaselineWarnAgeDays or BaselineStaleAgeDays'
    }

    It 'says nothing about freshness when there is no baseline to be fresh' {
        $f = & $script:Module { param($p) Test-TripwireBaselineFreshness -Baseline $null -AsOf $null -Policy $p } $script:Policy
        $f.Stale | Should -BeFalse
        $f.Warn | Should -BeFalse
    }

    It 'warns before it withholds, so the operator gets notice rather than a surprise' {
        $b = New-TestBaseline
        $b.generatedAt = '2026-05-25T14:00:00Z'   # 21 days: past the warning age, inside the stale age
        $f = & $script:Module { param($bb, $p) Test-TripwireBaselineFreshness -Baseline $bb -AsOf ([DateTime]::Parse('2026-06-15T14:00:00Z').ToUniversalTime()) -Policy $p } $b $script:Policy
        $f.Warn | Should -BeTrue
        $f.Stale | Should -BeFalse
        [Math]::Round($f.AgeDays) | Should -Be 21
    }
}

Describe 'Suppression runs before scoring' {

    It 'suppresses an actor on the tenant allowlist however anomalous the touch looks' {
        $b = New-TestBaseline -SuppressedActors @('actor-1')
        $t = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline $b -DistinctDecoyCount 6 -Policy $script:Policy
        $trip.Band | Should -Be 'Suppressed'
        $trip.Confidence | Should -Be 0
        $trip.SuppressionReason | Should -Match 'allowlist'
    }

    It 'suppresses the planter touching a decoy inside the provisioning window' {
        $decoy = New-TestDecoy -PlantedAt '2026-06-15T09:00:00Z' -PlantedBy 'admin@contoso.com'
        $t = New-TestTouch -Timestamp '2026-06-15T09:05:00Z' -ActorUpn 'admin@contoso.com'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy $decoy -Baseline (New-TestBaseline) -Policy $script:Policy
        $trip.Band | Should -Be 'Suppressed'
        $trip.SuppressionReason | Should -Match 'provisioning window'
    }

    It 'does NOT suppress the planter once the provisioning window has closed' {
        $decoy = New-TestDecoy -PlantedAt '2026-06-15T09:00:00Z' -PlantedBy 'admin@contoso.com'
        $t = New-TestTouch -Timestamp '2026-06-15T09:20:00Z' -ActorUpn 'admin@contoso.com'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy $decoy -Baseline (New-TestBaseline) -Policy $script:Policy
        $trip.Band | Should -Not -Be 'Suppressed'
    }

    It 'does NOT suppress a different actor inside the provisioning window' {
        $decoy = New-TestDecoy -PlantedAt '2026-06-15T09:00:00Z' -PlantedBy 'admin@contoso.com'
        $t = New-TestTouch -Timestamp '2026-06-15T09:05:00Z' -ActorUpn 'someone.else@contoso.com'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy $decoy -Baseline (New-TestBaseline) -Policy $script:Policy
        $trip.Band | Should -Not -Be 'Suppressed'
    }

    It 'still RETURNS the suppressed trip with its reason, rather than dropping it' {
        $b = New-TestBaseline -SuppressedActors @('actor-1')
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline $b -Policy $script:Policy
        $trip | Should -Not -BeNullOrEmpty
        $trip.TouchId | Should -Be 'touch-1'
    }
}

Describe 'Composition, banding and degradation' {

    It 'reaches High only with corroboration, and reports every signal' {
        $t = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) `
            -DistinctDecoyCount 4 -Policy $script:Policy
        $trip.Band | Should -Be 'High'
        $trip.Confidence | Should -BeGreaterOrEqual 75
        @($trip.Signals).Count | Should -Be 4
    }

    It 'bands Medium between the two thresholds' {
        # Pristine decoy + unseen country, no fan-out, peak hour: 40 + 25 = 65.
        $t = New-TestTouch -Timestamp '2026-06-15T14:00:00Z' -Country 'KP' -Asn '7922'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) -Policy $script:Policy
        $trip.Confidence | Should -Be 65
        $trip.Band | Should -Be 'Medium'
    }

    It 'a score landing exactly on the threshold is IN the High band, not below it' {
        # Purity 40 + unseen country 25 + no fan-out + a dead hour worth the full 10 = 75.0.
        # The boundary is inclusive by design, and an off-by-one here would quietly move
        # every borderline incident out of the band containment is allowed to act on.
        $hours = @(50, 40, 30, 0, 20, 30, 60, 80, 90, 100, 100, 95, 90, 88, 100, 95, 80, 50, 25, 10, 6, 4, 3, 2)
        $b = New-TestBaseline -Hours $hours
        $t = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '7922'
        $trip = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline $b -Policy $script:Policy
        $trip.Confidence | Should -Be 75
        $trip.Band | Should -Be 'High'
    }

    It 'marks a trip Degraded and names what was withheld' {
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline $null -Policy $script:Policy
        $trip.Degraded | Should -BeTrue
        $trip.Withheld | Should -Contain 'OriginAnomaly'
        $trip.Withheld | Should -Contain 'OffHours'
    }

    It 'a withheld signal LOWERS the score: it is never renormalised away' {
        # Identical touch, once with a baseline and once without. The blind run must not be
        # able to out-score the informed one.
        $t = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512'
        $informed = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) -DistinctDecoyCount 4 -Policy $script:Policy
        $blind = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline $null -DistinctDecoyCount 4 -Policy $script:Policy
        $blind.Confidence | Should -BeLessThan $informed.Confidence
        $blind.Confidence | Should -Be 65
    }

    It 'is deterministic: the same inputs give the same score twice' {
        $t = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512'
        $a = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) -DistinctDecoyCount 3 -Policy $script:Policy
        $b = Measure-TripwireConfidence -Touch $t -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) -DistinctDecoyCount 3 -Policy $script:Policy
        $a.Confidence | Should -Be $b.Confidence
    }
}
