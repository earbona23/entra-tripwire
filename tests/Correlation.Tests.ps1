#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Fan-out correlation, and the timestamp normalisation it depends on.

    Fan-out is the signal that carries a trip into the band where containment becomes
    eligible, so getting it wrong is not a scoring inaccuracy -- it is an automated action
    on the wrong person. These tests pin the three properties that keep it honest: distinct
    decoys rather than events, a real time window, and no bucketing of anonymous actors.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'EntraTripwire'
    Import-Module (Join-Path $script:SourceRoot 'EntraTripwire.psd1') -Force
    $script:Module = Get-Module EntraTripwire
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Baseline = New-TestBaseline
    $script:Decoys = @(
        New-TestDecoy -Id 'decoy-1' -DisplayName 'd1' -ObjectId 'o1'
        New-TestDecoy -Id 'decoy-2' -DisplayName 'd2' -ObjectId 'o2'
        New-TestDecoy -Id 'decoy-3' -DisplayName 'd3' -ObjectId 'o3'
        New-TestDecoy -Id 'decoy-4' -DisplayName 'd4' -ObjectId 'o4'
    )
}

Describe 'Timestamp normalisation' {

    It 'treats a Z-suffixed string, a Utc DateTime and a DateTimeOffset as the same instant' {
        $a = & $script:Module { ConvertTo-TripwireUtc '2026-06-15T09:00:00Z' }
        $b = & $script:Module { ConvertTo-TripwireUtc ([DateTime]::Parse('2026-06-15T09:00:00Z').ToUniversalTime()) }
        $c = & $script:Module { ConvertTo-TripwireUtc ([DateTimeOffset]::Parse('2026-06-15T11:00:00+02:00')) }
        $a | Should -Be $b
        $a | Should -Be $c
        $a.Kind | Should -Be 'Utc'
    }

    It 'REGRESSION: a string plantedAt and a Utc touch are compared in the same frame' {
        # A [DateTime] cast of an ISO string yields Kind=Local, which shifts the value by the
        # machine offset. Before ConvertTo-TripwireUtc this made the provisioning-grace window
        # unmatchable on any machine not running at UTC+0 -- correct in CI, broken in Santo
        # Domingo, and silent in both.
        $decoy = New-TestDecoy -PlantedAt '2026-06-15T09:00:00Z' -PlantedBy 'admin@contoso.com'
        $touch = New-TestTouch -Timestamp '2026-06-15T09:05:00Z' -ActorUpn 'admin@contoso.com'
        $reason = & $script:Module { param($t, $d, $b, $p) Test-TripwireSuppression -Touch $t -Decoy $d -Baseline $b -Policy $p } `
            $touch $decoy $script:Baseline (Get-TripwirePolicy)
        $reason | Should -Match 'provisioning window'
    }
}

Describe 'Fan-out correlation' {

    It 'counts DISTINCT decoys, not events: one decoy retried many times is not a sweep' {
        $touches = 1..8 | ForEach-Object {
            New-TestTouch -Id "t$_" -DecoyId 'decoy-1' -Timestamp ('2026-06-15T14:{0:00}:00Z' -f $_)
        }
        $trips = @(Invoke-TripwireAnalysis -Touch $touches -Decoy $script:Decoys -Baseline $script:Baseline)
        @($trips | ForEach-Object { $_.DistinctDecoys } | Sort-Object -Unique) | Should -Be @(1)
        ($trips | Where-Object { $_.Signals | Where-Object { $_.Name -eq 'CrossDecoyFanOut' -and $_.Raw -gt 0 } }) | Should -BeNullOrEmpty
    }

    It 'counts four decoys swept by one actor as full fan-out' {
        $touches = @(
            New-TestTouch -Id 't1' -DecoyId 'decoy-1' -Timestamp '2026-06-15T14:00:00Z'
            New-TestTouch -Id 't2' -DecoyId 'decoy-2' -Timestamp '2026-06-15T14:05:00Z'
            New-TestTouch -Id 't3' -DecoyId 'decoy-3' -Timestamp '2026-06-15T14:09:00Z'
            New-TestTouch -Id 't4' -DecoyId 'decoy-4' -Timestamp '2026-06-15T14:11:00Z'
        )
        $trips = @(Invoke-TripwireAnalysis -Touch $touches -Decoy $script:Decoys -Baseline $script:Baseline)
        @($trips | ForEach-Object { $_.DistinctDecoys } | Sort-Object -Unique) | Should -Be @(4)
    }

    It 'does not correlate across the window: touches a day apart are separate incidents' {
        $touches = @(
            New-TestTouch -Id 't1' -DecoyId 'decoy-1' -Timestamp '2026-06-15T14:00:00Z'
            New-TestTouch -Id 't2' -DecoyId 'decoy-2' -Timestamp '2026-06-16T14:00:00Z'
        )
        $trips = @(Invoke-TripwireAnalysis -Touch $touches -Decoy $script:Decoys -Baseline $script:Baseline)
        @($trips | ForEach-Object { $_.DistinctDecoys } | Sort-Object -Unique) | Should -Be @(1)
    }

    It 'does not correlate two different actors into one sweep' {
        $touches = @(
            New-TestTouch -Id 't1' -DecoyId 'decoy-1' -ActorId 'actor-a' -Timestamp '2026-06-15T14:00:00Z'
            New-TestTouch -Id 't2' -DecoyId 'decoy-2' -ActorId 'actor-b' -Timestamp '2026-06-15T14:02:00Z'
        )
        $trips = @(Invoke-TripwireAnalysis -Touch $touches -Decoy $script:Decoys -Baseline $script:Baseline)
        @($trips | ForEach-Object { $_.DistinctDecoys } | Sort-Object -Unique) | Should -Be @(1)
    }

    It 'NEVER buckets unidentifiable actors together: anonymous noise cannot manufacture fan-out' {
        # No object id and no source address. Grouping these would invent a sweep out of
        # unrelated events and push them into the containment band.
        $touches = 1..4 | ForEach-Object {
            New-TestTouch -Id "t$_" -DecoyId "decoy-$_" -ActorId '' -ActorUpn '' -Ip '' -Timestamp '2026-06-15T14:00:00Z'
        }
        $trips = @(Invoke-TripwireAnalysis -Touch $touches -Decoy $script:Decoys -Baseline $script:Baseline)
        @($trips | ForEach-Object { $_.DistinctDecoys } | Sort-Object -Unique) | Should -Be @(1)
    }

    It 'falls back to the source address when there is no directory object id' {
        $touches = @(
            New-TestTouch -Id 't1' -DecoyId 'decoy-1' -ActorId '' -Ip '198.51.100.9' -Timestamp '2026-06-15T14:00:00Z'
            New-TestTouch -Id 't2' -DecoyId 'decoy-2' -ActorId '' -Ip '198.51.100.9' -Timestamp '2026-06-15T14:03:00Z'
        )
        $trips = @(Invoke-TripwireAnalysis -Touch $touches -Decoy $script:Decoys -Baseline $script:Baseline)
        @($trips | ForEach-Object { $_.DistinctDecoys } | Sort-Object -Unique) | Should -Be @(2)
    }

    It 'scores a touch whose decoy is missing from the inventory as degraded, not as clean' {
        $touches = @(New-TestTouch -Id 't1' -DecoyId 'decoy-unknown')
        $trips = @(Invoke-TripwireAnalysis -Touch $touches -Decoy $script:Decoys -Baseline $script:Baseline)
        $trips[0].Degraded | Should -BeTrue
        $trips[0].Withheld | Should -Contain 'DecoyPurity'
    }
}

<#
    The baseline's age is now read, and the question of WHERE it is announced is a usability
    one with a security edge: a per-touch message would print once per record in a batch of
    two thousand, and a message that floods is a message that is filtered out.
#>
Describe 'Baseline age is announced once per batch' {

    It 'warns once for the whole batch, not once per touch' {
        $old = New-TestBaseline
        $old.generatedAt = '2026-05-01T00:00:00Z'
        $touches = @(1..6 | ForEach-Object {
                New-TestTouch -Id "t$_" -DecoyId 'decoy-1' -Timestamp ('2026-06-15T14:{0:00}:00Z' -f $_)
            })
        $warnings = @()
        $null = Invoke-TripwireAnalysis -Touch $touches -Decoy $script:Decoys -Baseline $old `
            -WarningVariable warnings -WarningAction SilentlyContinue
        @($warnings | Where-Object { $_ -match 'baseline' }).Count | Should -Be 1
    }

    # The batch line says the signals are WITHHELD, so it has to be the stale verdict that
    # drives it and not a guess about the calendar.
    It 'tells the operator the whole batch was scored with those signals withheld' {
        $old = New-TestBaseline
        $old.generatedAt = '2026-01-01T00:00:00Z'
        $warnings = @()
        $trips = @(Invoke-TripwireAnalysis -Touch @(New-TestTouch -Timestamp '2026-06-15T14:00:00Z') `
                -Decoy $script:Decoys -Baseline $old -WarningVariable warnings -WarningAction SilentlyContinue)
        ($warnings -join ' ') | Should -Match 'WITHHELD'
        $trips[0].Withheld | Should -Contain 'OriginAnomaly'
    }

    It 'says nothing when the baseline is current' {
        $warnings = @()
        $null = Invoke-TripwireAnalysis -Touch @(New-TestTouch -Timestamp '2026-06-05T14:00:00Z') `
            -Decoy $script:Decoys -Baseline $script:Baseline -WarningVariable warnings -WarningAction SilentlyContinue
        @($warnings | Where-Object { $_ -match 'baseline' }).Count | Should -Be 0
    }
}
