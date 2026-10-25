#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    What the detector does when its inputs are ugly.

    Almost every test in this file was written against a measured defect and fails against
    the code as it stood before; the rest pin boundary behaviour that a rewrite in the same
    area had to preserve. They share a single theme, which is the failure mode that matters
    most in a security control: the detector going quiet, or going loud, for a reason that
    has nothing to do with the tenant.

    Two shapes of that, and PowerShell supplies both:

      * A comparison against $null that reads as success. `50 -ge $null` is $true, so a
        policy that lost its High threshold banded every trip High -- and High is the only
        band containment acts on.
      * A missing value that casts to 0 without complaint. [double]$null is 0, so a policy
        that lost a weight reported a signal at full raw strength contributing nothing,
        with the trip NOT marked degraded.

    And one that is not about $null at all: a single malformed record raising a terminating
    error and taking every other finding in the batch with it. A run that found intrusions
    returned nothing, which is indistinguishable from a quiet tenant.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'EntraTripwire'
    Import-Module (Join-Path $script:SourceRoot 'EntraTripwire.psd1') -Force
    $script:Module = Get-Module EntraTripwire
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
}

Describe 'An incomplete policy is refused instead of silently reinterpreted' {

    # Measured before the guard existed: this exact override produced seven High trips from
    # the shipped fixtures, the lowest of them scoring 34.6, because `34.6 -ge $null` is
    # $true. A typo in a config file turned the tool into "contain everything".
    It 'refuses an override whose Threshold object lost a member, naming the member' {
        { Get-TripwirePolicy -Override @{ Threshold = [pscustomobject]@{ Hihg = 75; Medium = 45 } } } |
            Should -Throw -ExpectedMessage '*Policy.Threshold.High is missing or not a number*'
    }

    It 'refuses an override whose Weights object lost a member' {
        { Get-TripwirePolicy -Override @{ Weights = [pscustomobject]@{ DecoyPurity = 0.40 } } } |
            Should -Throw -ExpectedMessage '*Policy.Weights.OriginAnomaly is missing or not a number*'
    }

    It 'refuses a threshold that is present but not a number' {
        { Get-TripwirePolicy -Override @{ Threshold = [pscustomobject]@{ High = 'high'; Medium = 45 } } } |
            Should -Throw -ExpectedMessage '*Policy.Threshold.High*'
    }

    It 'refuses a High band below the Medium band, which would make containment unreachable' {
        { Get-TripwirePolicy -Override @{ Threshold = [pscustomobject]@{ High = 20; Medium = 45 } } } |
            Should -Throw -ExpectedMessage '*unreachable*'
    }

    It 'refuses empty tier sets rather than scoring their signal at zero forever' {
        { Get-TripwirePolicy -Override @{ PurityTiers = @() } } |
            Should -Throw -ExpectedMessage '*PurityTiers is empty*'
        { Get-TripwirePolicy -Override @{ FanOutTiers = @() } } |
            Should -Throw -ExpectedMessage '*FanOutTiers is empty*'
    }

    It 'refuses a hand-built policy handed straight to the scoring engine' {
        $bogus = [pscustomobject]@{ Weights = [pscustomobject]@{ DecoyPurity = 1.0 } }
        { Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) `
                -Baseline (New-TestBaseline) -Policy $bogus } | Should -Throw
    }

    It 'still accepts every legitimate override, and keeps the untouched keys' {
        $p = Get-TripwirePolicy -Override @{ ImpossibleTravelKph = 1200; CorrelationWindowMinutes = 120 }
        $p.ImpossibleTravelKph | Should -Be 1200
        $p.CorrelationWindowMinutes | Should -Be 120
        $p.Threshold.High | Should -Be 75
        $p.Weights.OffHours | Should -Be 0.10
    }

    It 'warns, rather than refuses, when a deliberate recalibration stops summing to 1.00' {
        $warnings = @()
        $p = Get-TripwirePolicy -Override @{
            Weights = [pscustomobject]@{ DecoyPurity = 0.50; OriginAnomaly = 0.25; CrossDecoyFanOut = 0.25; OffHours = 0.10 }
        } -WarningVariable warnings -WarningAction SilentlyContinue
        $p.Weights.DecoyPurity | Should -Be 0.50
        ($warnings -join ' ') | Should -Match 'no longer a percentage'
    }
}

Describe 'A record with no usable timestamp' {

    BeforeEach {
        $script:Decoys = @(New-TestDecoy)
        $script:Baseline = New-TestBaseline
        # A touch with no timestamp has no position in time, so the baseline's age for it is
        # measured against the clock rather than against the touch. Pinned current here on
        # purpose: with a fixed date in the fixture, these tests would quietly stop
        # exercising the no-timestamp guard the day the fixture passed the stale age -- the
        # signal would be withheld for being stale instead, the assertions would still pass,
        # and scripts/mutation-test.ps1 reported exactly that as a surviving mutant.
        $script:Baseline.generatedAt = [DateTime]::UtcNow.AddDays(-1).ToString('o')
        $script:Good = New-TestTouch -Id 'good-1' -Timestamp '2026-06-15T03:00:00Z' -Country 'KP'
        $script:NoTime = New-TestTouch -Id 'no-time'
        $script:NoTime.timestamp = $null
        $script:BadTime = New-TestTouch -Id 'bad-time'
        $script:BadTime.timestamp = 'not-a-date'
    }

    # The whole point. Before the guard, this threw
    # 'Cannot find an overload for "op_Subtraction"' out of Invoke-TripwireAnalysis and the
    # good trip was never returned.
    It 'does not take the rest of the batch down with it' {
        $trips = @(Invoke-TripwireAnalysis -Touch @($script:NoTime, $script:BadTime, $script:Good) `
                -Decoy $script:Decoys -Baseline $script:Baseline)
        $trips.Count | Should -Be 3
        @($trips | Where-Object TouchId -eq 'good-1').Count | Should -Be 1
    }

    It 'withholds the off-hours signal instead of inventing an hour for it' {
        $trip = Measure-TripwireConfidence -Touch $script:NoTime -Decoy (New-TestDecoy) -Baseline $script:Baseline
        $trip.Withheld | Should -Contain 'OffHours'
        $trip.Degraded | Should -BeTrue
        ($trip.Signals | Where-Object Name -eq 'OffHours').Weighted | Should -Be 0
    }

    # Hour 0 is the deadest hour in the default test tenant, so the old behaviour -- had
    # the null index not thrown -- would have scored a missing timestamp as the strongest
    # possible off-hours anomaly. Withheld and maximum are opposite answers.
    It 'is never scored as if it happened at midnight' {
        $midnight = New-TestTouch -Id 'midnight' -Timestamp '2026-06-15T00:00:00Z'
        $atMidnight = Measure-TripwireConfidence -Touch $midnight -Decoy (New-TestDecoy) -Baseline $script:Baseline
        $undated = Measure-TripwireConfidence -Touch $script:NoTime -Decoy (New-TestDecoy) -Baseline $script:Baseline

        ($atMidnight.Signals | Where-Object Name -eq 'OffHours').Raw | Should -BeGreaterThan 0.9
        ($undated.Signals | Where-Object Name -eq 'OffHours').Available | Should -BeFalse
        $undated.Confidence | Should -BeLessThan $atMidnight.Confidence
    }

    It 'is never correlated into another actor window, so it cannot manufacture fan-out' {
        # Same actor, same window on paper -- but one of them has no time to place.
        $a = New-TestTouch -Id 'a' -DecoyId 'decoy-1' -Timestamp '2026-06-15T14:00:00Z'
        $b = New-TestTouch -Id 'b' -DecoyId 'decoy-2' -Timestamp '2026-06-15T14:10:00Z'
        $c = New-TestTouch -Id 'c' -DecoyId 'decoy-3'
        $c.timestamp = $null

        $trips = @(Invoke-TripwireAnalysis -Touch @($a, $b, $c) -Decoy @(
                New-TestDecoy -Id 'decoy-1'; New-TestDecoy -Id 'decoy-2'; New-TestDecoy -Id 'decoy-3') `
                -Baseline $script:Baseline)

        (@($trips | Where-Object TouchId -eq 'a')).DistinctDecoys | Should -Be 2
        (@($trips | Where-Object TouchId -eq 'c')).DistinctDecoys | Should -Be 1
    }

    # Suppression HIDES evidence. When it cannot establish that the touch really fell
    # inside the provisioning window, declining to suppress is the only safe answer.
    It 'is not suppressed by the provisioning-grace rule it cannot be placed in' {
        $decoy = New-TestDecoy -PlantedAt '2026-06-15T13:55:00Z' -PlantedBy 'intruder@contoso.com'
        $trip = Measure-TripwireConfidence -Touch $script:NoTime -Decoy $decoy -Baseline $script:Baseline
        $trip.Band | Should -Not -Be 'Suppressed'
        $trip.SuppressionReason | Should -BeNullOrEmpty
    }

    # The collection path, not just the scoring path. Note the UNPARSEABLE string rather
    # than $null: ConvertTo-TripwireUtc already returns $null for $null, so only a value
    # that fails to parse distinguishes the throwing resolver from the tolerant one. A test
    # written with $null here passes against both and proves nothing -- which is exactly
    # what scripts/mutation-test.ps1 reported when the mutant survived.
    It 'survives a record whose timestamp is present but not a date' {
        foreach ($stamp in @($null, '', 'not-a-date', 'yesterday', '2026-13-45T99:99:99Z')) {
            $touch = & $script:Module {
                param($when)
                $index = Get-TripwireDecoyIndex -Decoy @([pscustomobject]@{
                        id = 'd1'; objectId = 'u-1'; appId = $null; upn = 'bait@contoso.com'; displayName = 'bait'
                    })
                ConvertTo-TripwireTouchFromSignIn -Record ([pscustomobject]@{
                        id = 'si-x'; userId = 'u-1'; userPrincipalName = 'bait@contoso.com'
                        createdDateTime = $when; appDisplayName = 'App'; status = [pscustomobject]@{ errorCode = 0 }
                    }) -DecoyIndex $index
            } $stamp

            $touch | Should -Not -BeNullOrEmpty -Because "a record with createdDateTime '$stamp' is still a touch on a decoy"
            $touch.timestamp | Should -BeNullOrEmpty
            $touch.decoyId | Should -Be 'd1'
        }
    }

    It 'survives a directory-audit record whose activityDateTime is not a date' {
        $touch = & $script:Module {
            $index = Get-TripwireDecoyIndex -Decoy @([pscustomobject]@{
                    id = 'd1'; objectId = 'u-1'; appId = $null; upn = 'bait@contoso.com'; displayName = 'bait'
                })
            ConvertTo-TripwireTouchFromAudit -Record ([pscustomobject]@{
                    id = 'au-x'; activityDateTime = 'not-a-date'; activityDisplayName = 'Read user'
                    result = 'success'
                    targetResources = @([pscustomobject]@{ id = 'u-1'; userPrincipalName = 'bait@contoso.com'; displayName = 'bait' })
                    initiatedBy = [pscustomobject]@{ user = [pscustomobject]@{ id = 'a-1'; userPrincipalName = 'x@y.com'; ipAddress = '203.0.113.9' } }
                }) -DecoyIndex $index
        }
        $touch | Should -Not -BeNullOrEmpty
        $touch.timestamp | Should -BeNullOrEmpty
    }

    # The decoy's plantedAt is hand-editable too, and the suppression rule subtracts it.
    # [DateTime] minus $null throws (the reverse order does not), so an unparseable
    # plantedAt took the run down from inside a rule whose only job is to stay quiet.
    It 'does not crash on a decoy whose plantedAt is not a date' {
        $decoy = New-TestDecoy -PlantedBy 'intruder@contoso.com'
        $decoy.plantedAt = 'some time last week'
        { Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy $decoy -Baseline (New-TestBaseline) | Out-Null } |
            Should -Not -Throw
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy $decoy -Baseline (New-TestBaseline)
        $trip.Band | Should -Not -Be 'Suppressed'
    }
}

Describe 'Correlation stays correct while it stays fast' {

    # The window sweep was rewritten from a naive rescan into a sorted two-pointer pass.
    # These pin the boundary behaviour the rewrite had to preserve exactly.
    It 'counts a touch exactly on the window edge, and not one past it' {
        $policy = Get-TripwirePolicy
        $edge = $policy.CorrelationWindowMinutes
        $centre = [DateTime]::Parse('2026-06-15T12:00:00Z').ToUniversalTime()

        $touches = @(
            New-TestTouch -Id 'centre' -DecoyId 'decoy-1' -Timestamp $centre.ToString('o')
            New-TestTouch -Id 'on-edge' -DecoyId 'decoy-2' -Timestamp $centre.AddMinutes($edge).ToString('o')
            New-TestTouch -Id 'past-edge' -DecoyId 'decoy-3' -Timestamp $centre.AddMinutes($edge + 1).ToString('o')
        )
        $decoys = @(New-TestDecoy -Id 'decoy-1'; New-TestDecoy -Id 'decoy-2'; New-TestDecoy -Id 'decoy-3')
        $trips = @(Invoke-TripwireAnalysis -Touch $touches -Decoy $decoys -Baseline (New-TestBaseline))

        (@($trips | Where-Object TouchId -eq 'centre')).DistinctDecoys | Should -Be 2
    }

    It 'still counts distinct decoys rather than events when one decoy is retried' {
        $touches = @(1..12 | ForEach-Object {
                New-TestTouch -Id "retry-$_" -DecoyId 'decoy-1' `
                    -Timestamp ([DateTime]::Parse('2026-06-15T12:00:00Z').AddMinutes($_).ToString('o'))
            })
        $trips = @(Invoke-TripwireAnalysis -Touch $touches -Decoy @(New-TestDecoy -Id 'decoy-1') -Baseline (New-TestBaseline))
        @($trips | ForEach-Object { $_.DistinctDecoys } | Sort-Object -Unique) | Should -Be 1
    }
}

Describe 'A hand-edited decoy inventory' {

    # legitimateUseCount is the field the documentation tells the operator to maintain by
    # hand, so it is the field that can arrive as a word. [int]'three' throws, and it threw
    # inside the signal that carries 40% of the weight.
    It 'withholds purity rather than crashing when legitimateUseCount is not a number' {
        $decoy = New-TestDecoy
        $decoy.legitimateUseCount = 'three'
        # Assigning inside the Should scriptblock would scope the variable to that block.
        { Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy $decoy -Baseline (New-TestBaseline) | Out-Null } |
            Should -Not -Throw
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy $decoy -Baseline (New-TestBaseline)
        $trip.Withheld | Should -Contain 'DecoyPurity'
        ($trip.Signals | Where-Object Name -eq 'DecoyPurity').Rationale | Should -Match 'not a whole number'
    }

    # Withheld, not pristine. Asserting purity you cannot establish is the one direction
    # that puts a trip into the band containment acts on.
    It 'does not score an unreadable purity as a never-used decoy' {
        $pristine = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy -LegitimateUseCount 0) `
            -Baseline (New-TestBaseline) -DistinctDecoyCount 4
        $broken = New-TestDecoy
        $broken.legitimateUseCount = ''
        $unknown = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy $broken `
            -Baseline (New-TestBaseline) -DistinctDecoyCount 4

        $unknown.Confidence | Should -BeLessThan $pristine.Confidence
        $unknown.Degraded | Should -BeTrue
    }

    It 'still reads a count that arrived as a numeric string' {
        $decoy = New-TestDecoy
        $decoy.legitimateUseCount = '5'
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy $decoy -Baseline (New-TestBaseline)
        ($trip.Signals | Where-Object Name -eq 'DecoyPurity').Available | Should -BeTrue
        ($trip.Signals | Where-Object Name -eq 'DecoyPurity').Raw | Should -Be 0.20
    }
}

<#
    The read gateway. Its own documentation names the failure that matters -- "a detector
    that gives up halfway through the sign-in log reports fewer touches than happened, the
    failure mode that looks like good news" -- and until now the paging, retry and
    truncation code that avoids it had no behavioural test at all: only an assertion about
    the text of the file. Every case below drives it through a stub and asserts on what
    came back out.
#>
Describe 'The read gateway follows paging and never reports a partial read as complete' {

    BeforeEach {
        Remove-Item Env:\ETW_TEST_PAGES, Env:\ETW_TEST_FAIL_TIMES, Env:\ETW_TEST_STATUS -ErrorAction SilentlyContinue
        . $script:Module {
            $script:TestRequestLog = [System.Collections.Generic.List[string]]::new()
            $script:TestAttempts = 0
            $script:TestSleeps = [System.Collections.Generic.List[int]]::new()

            # The backoff is real and deliberate, but six seconds of it per test is six
            # seconds the suite spends asleep -- multiplied by every run the mutation
            # harness makes. The delay is RECORDED instead of slept, which also lets the
            # backoff curve itself be asserted on.
            function Start-Sleep { param([int] $Seconds, [int] $Milliseconds) $script:TestSleeps.Add($Seconds) }
            function Invoke-MgGraphRequest {
                param([string] $Method, [string] $Uri, $Body, $OutputType, $ErrorAction)
                $script:TestRequestLog.Add("$Method $Uri")

                # Fail the first N attempts with the configured HTTP status.
                $script:TestAttempts++
                $failTimes = if ($env:ETW_TEST_FAIL_TIMES) { [int] $env:ETW_TEST_FAIL_TIMES } else { 0 }
                if ($script:TestAttempts -le $failTimes) {
                    $status = if ($env:ETW_TEST_STATUS) { [int] $env:ETW_TEST_STATUS } else { 429 }
                    $ex = [System.Exception]::new("simulated $status")
                    $err = [System.Management.Automation.ErrorRecord]::new($ex, 'Simulated', 'NotSpecified', $null)
                    $err.Exception | Add-Member -NotePropertyName Response `
                        -NotePropertyValue ([pscustomobject]@{ StatusCode = $status }) -Force
                    throw $err
                }

                # Serve $env:ETW_TEST_PAGES pages of one record each.
                $pages = if ($env:ETW_TEST_PAGES) { [int] $env:ETW_TEST_PAGES } else { 1 }
                $seen = @($script:TestRequestLog | Where-Object { $_ -notmatch 'simulated' }).Count
                $result = @{ value = @([pscustomobject]@{ id = "record-$seen" }) }
                if ($seen -lt $pages) { $result['@odata.nextLink'] = "/next/$seen" }
                return [pscustomobject]$result
            }
        }
    }

    AfterEach {
        Remove-Item Env:\ETW_TEST_PAGES, Env:\ETW_TEST_FAIL_TIMES, Env:\ETW_TEST_STATUS -ErrorAction SilentlyContinue
        # Both stubs were dot-sourced into the module scope, so both have to go.
        . $script:Module { Remove-Item Function:\Start-Sleep -ErrorAction SilentlyContinue }
        Install-GraphStub -Module $script:Module
    }

    It 'follows @odata.nextLink to the end and returns every record' {
        $env:ETW_TEST_PAGES = '4'
        $records = & $script:Module { @(Invoke-TripwireGraphRequest -Uri '/v1.0/auditLogs/signIns') }
        $records.Count | Should -Be 4
        @($records | ForEach-Object { $_.id }) | Should -Be @('record-1', 'record-2', 'record-3', 'record-4')
    }

    # A truncated read is the one that looks like good news. It must warn, loudly, and the
    # warning must say the results are incomplete rather than merely that a limit was hit.
    It 'warns that results are TRUNCATED when it stops at the page limit' {
        $env:ETW_TEST_PAGES = '50'
        # -WarningVariable cannot cross the module-scope boundary, so the warning stream is
        # merged into output with 3>&1 and picked out by record type.
        $out = & $script:Module { Invoke-TripwireGraphRequest -Uri '/v1.0/auditLogs/signIns' -MaxPages 3 } 3>&1
        $warnings = @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        $records = @($out | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })

        $records.Count | Should -Be 3
        ($warnings -join ' ') | Should -Match 'TRUNCATED'
        (& $script:Module { $script:TestRequestLog.Count }) | Should -Be 3
    }

    It 'retries a 429 with exponential backoff and still returns the records' {
        $env:ETW_TEST_FAIL_TIMES = '2'
        $env:ETW_TEST_STATUS = '429'
        $records = & $script:Module { @(Invoke-TripwireGraphRequest -Uri '/v1.0/auditLogs/signIns' -MaxRetry 4 -WarningAction SilentlyContinue) }
        $records.Count | Should -Be 1
        (& $script:Module { $script:TestAttempts }) | Should -Be 3
        # Backing off at a FIXED interval would hammer a throttled tenant; the curve is
        # part of the contract with Graph, so it is asserted rather than assumed.
        (& $script:Module { @($script:TestSleeps) }) | Should -Be @(2, 4)
    }

    It 'retries a 5xx, which is a server fault and not a reason to report an empty log' {
        $env:ETW_TEST_FAIL_TIMES = '1'
        $env:ETW_TEST_STATUS = '503'
        $records = & $script:Module { @(Invoke-TripwireGraphRequest -Uri '/v1.0/auditLogs/signIns' -WarningAction SilentlyContinue) }
        $records.Count | Should -Be 1
    }

    # The critical one. Exhausted retries must THROW, so the caller never mistakes a failed
    # read for an empty one. Returning @() here is how a tool says "nothing happened".
    It 'throws rather than returning an empty set when the retries are exhausted' {
        $env:ETW_TEST_FAIL_TIMES = '99'
        $env:ETW_TEST_STATUS = '429'
        { & $script:Module { Invoke-TripwireGraphRequest -Uri '/v1.0/auditLogs/signIns' -MaxRetry 1 -WarningAction SilentlyContinue } } |
            Should -Throw -ExpectedMessage '*Graph GET failed*'
    }

    It 'does not retry a 403, which is a permissions problem a retry cannot fix' {
        $env:ETW_TEST_FAIL_TIMES = '99'
        $env:ETW_TEST_STATUS = '403'
        { & $script:Module { Invoke-TripwireGraphRequest -Uri '/v1.0/auditLogs/signIns' -MaxRetry 4 -WarningAction SilentlyContinue } } |
            Should -Throw
        (& $script:Module { $script:TestAttempts }) | Should -Be 1
    }

    It 'will not accept a page limit of zero, which would fetch nothing and report success' {
        { & $script:Module { Invoke-TripwireGraphRequest -Uri '/v1.0/auditLogs/signIns' -MaxPages 0 } } | Should -Throw
    }
}

<#
    A baseline is a JSON file the documentation tells the operator to edit by hand -- the
    suppression allowlist lives in it, and so does every count the origin and off-hours
    signals divide by. So every number in it can arrive as a word, and the casts that read
    them ([int], [double], and the [double] parameter binding in Get-TripwireDistanceKm)
    all throw on one.

    They throw INSIDE A SIGNAL, which is the worst place available: scoring runs per touch
    inside Invoke-TripwireAnalysis, so one bad character aborted the whole batch and a run
    that found intrusions returned nothing. Nothing is what a quiet tenant returns.
#>
Describe 'A hand-edited baseline' {

    BeforeEach {
        $script:Decoy = New-TestDecoy
        $script:Touch = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'US' -Asn '7922'
    }

    It 'withholds the origin signal rather than crashing when totalSignIns is not a number' {
        $b = New-TestBaseline
        $b.totalSignIns = 'lots'
        { Measure-TripwireConfidence -Touch $script:Touch -Decoy $script:Decoy -Baseline $b | Out-Null } |
            Should -Not -Throw
        $trip = Measure-TripwireConfidence -Touch $script:Touch -Decoy $script:Decoy -Baseline $b
        $trip.Withheld | Should -Contain 'OriginAnomaly'
        ($trip.Signals | Where-Object Name -eq 'OriginAnomaly').Rationale | Should -Match 'not a number'
    }

    # The direction is the whole point. An ABSENT country means the tenant has never been
    # seen there and scores the full anomaly; a country whose count is corrupt means
    # nothing is known. Scoring the second as the first manufactures evidence out of a typo.
    It 'does not score an unreadable country count as a country never seen' {
        $b = New-TestBaseline -Countries @{ US = 'many'; CA = 50 }
        $trip = Measure-TripwireConfidence -Touch $script:Touch -Decoy $script:Decoy -Baseline $b
        $signal = $trip.Signals | Where-Object Name -eq 'OriginAnomaly'
        $signal.Available | Should -BeFalse
        $signal.Raw | Should -Be 0
        $signal.Rationale | Should -Match "count for country 'US'"
    }

    It 'does not score an unreadable autonomous-system count as one never seen' {
        $b = New-TestBaseline -Asns @{ '7922' = 'plenty' }
        $trip = Measure-TripwireConfidence -Touch $script:Touch -Decoy $script:Decoy -Baseline $b
        ($trip.Signals | Where-Object Name -eq 'OriginAnomaly').Available | Should -BeFalse
    }

    # A real finding still stands: the score is a floor, and an unreadable second component
    # could only have raised it. What must never happen is reporting a NORMAL origin on the
    # strength of a comparison nobody could make.
    It 'still reports an unseen country when it is the other component that is unreadable' {
        $b = New-TestBaseline -Countries @{ US = 940 } -Asns @{ '7922' = 'plenty' }
        $t = New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '7922'
        $signal = (Measure-TripwireConfidence -Touch $t -Decoy $script:Decoy -Baseline $b).Signals |
            Where-Object Name -eq 'OriginAnomaly'
        $signal.Available | Should -BeTrue
        $signal.Raw | Should -Be 1.0
    }

    It 'withholds the off-hours signal rather than crashing on a histogram bucket that is a word' {
        # Built by hand rather than through New-TestBaseline, whose -Hours is [int[]] and
        # would reject the very value a JSON file on disk can hold.
        $b = New-TestBaseline
        $b.hourHistogram = @(2, 1, 1, 'three', 1, 2, 5, 20, 60, 85, 95, 100, 98, 99, 100, 95, 80, 50, 25, 10, 6, 4, 3, 2)
        { Measure-TripwireConfidence -Touch $script:Touch -Decoy $script:Decoy -Baseline $b | Out-Null } |
            Should -Not -Throw
        $trip = Measure-TripwireConfidence -Touch $script:Touch -Decoy $script:Decoy -Baseline $b
        $trip.Withheld | Should -Contain 'OffHours'
        ($trip.Signals | Where-Object Name -eq 'OffHours').Rationale | Should -Match 'not a number'
    }

    # Get-TripwireDistanceKm binds its coordinates to [double], so a latitude of 'north'
    # throws during PARAMETER BINDING -- before any guard inside that function can run.
    It 'survives a last-seen position whose coordinates are not numbers' {
        $b = New-TestBaseline -ActorLastSeen @{
            'actor-1' = @{ timestamp = '2026-06-15T01:00:00Z'; country = 'US'; latitude = 'north'; longitude = 'west' }
        }
        $t = New-TestTouch -Timestamp '2026-06-15T03:20:00Z' -Country 'US' -Asn '7922' -Latitude 50.1109 -Longitude 8.6821
        { Measure-TripwireConfidence -Touch $t -Decoy $script:Decoy -Baseline $b | Out-Null } | Should -Not -Throw
        $signal = (Measure-TripwireConfidence -Touch $t -Decoy $script:Decoy -Baseline $b).Signals |
            Where-Object Name -eq 'OriginAnomaly'
        # The country and ASN are still judged; only impossible travel is unavailable.
        $signal.Available | Should -BeTrue
        $signal.Rationale | Should -Not -Match 'Impossible travel'
    }

    It 'does not take the rest of the batch down with one corrupt baseline field' {
        $b = New-TestBaseline
        $b.totalSignIns = 'lots'
        $touches = @(
            New-TestTouch -Id 'a' -DecoyId 'decoy-1' -Timestamp '2026-06-15T14:00:00Z'
            New-TestTouch -Id 'b' -DecoyId 'decoy-1' -Timestamp '2026-06-15T14:05:00Z'
        )
        $trips = @(Invoke-TripwireAnalysis -Touch $touches -Decoy @(New-TestDecoy -Id 'decoy-1') -Baseline $b)
        $trips.Count | Should -Be 2
    }
}

<#
    Collection, and the failure that looks like good news.

    The old read asked for the whole window in one chain of pages, filtered client-side,
    and stopped at the page limit with a warning. On a tenant with -Days 30 that is up to
    200,000 records a source: past the limit the run reports fewer touches than happened.

    The stub below serves one record per request and declares a window "dense" -- paging
    forever -- when it is longer than ETW_DENSE_MINUTES, which is how a busy span is
    simulated without generating one.
#>
Describe 'Collection reads its whole window, or says which part it did not' {

    BeforeEach {
        Remove-Item Env:\ETW_DENSE_MINUTES, Env:\ETW_REJECT -ErrorAction SilentlyContinue
        . $script:Module {
            $script:TestUris = [System.Collections.Generic.List[string]]::new()
            function Start-Sleep { param([int] $Seconds, [int] $Milliseconds) }
            function Invoke-MgGraphRequest {
                param([string] $Method, [string] $Uri, $Body, $OutputType, $ErrorAction)
                $script:TestUris.Add($Uri)

                if ($env:ETW_REJECT -and $Uri -match [regex]::Escape($env:ETW_REJECT)) {
                    $ex = [System.Exception]::new('Invalid filter clause specified for property')
                    $err = [System.Management.Automation.ErrorRecord]::new($ex, 'BadRequest', 'NotSpecified', $null)
                    $err.Exception | Add-Member -NotePropertyName Response `
                        -NotePropertyValue ([pscustomobject]@{ StatusCode = 400 }) -Force
                    throw $err
                }

                $minutes = 0.0
                if ($Uri -match '\sge\s(\S+)\sand\s\S+\slt\s([^\s&]+)') {
                    $minutes = ([DateTime]::Parse($Matches[2]).ToUniversalTime() -
                        [DateTime]::Parse($Matches[1]).ToUniversalTime()).TotalMinutes
                }
                $dense = if ($env:ETW_DENSE_MINUTES) { [double] $env:ETW_DENSE_MINUTES } else { -1 }

                $n = $script:TestUris.Count
                $record = if ($Uri -match 'signIns') {
                    [pscustomobject]@{
                        id                     = "si-$n"
                        createdDateTime        = '2026-06-15T14:00:00Z'
                        userId                 = 'obj-decoy-1'
                        userPrincipalName      = 'svc-decoy@contoso.com'
                        userDisplayName        = 'svc-decoy'
                        appId                  = 'app-unrelated'
                        appDisplayName         = 'Office 365 Exchange Online'
                        ipAddress              = '203.0.113.5'
                        autonomousSystemNumber = '7922'
                        status                 = [pscustomobject]@{ errorCode = 0 }
                        location               = [pscustomobject]@{ countryOrRegion = 'US' }
                    }
                }
                else {
                    [pscustomobject]@{
                        id = "au-$n"; activityDateTime = '2026-06-15T14:00:00Z'
                        activityDisplayName = 'Read user'; result = 'success'
                        targetResources = @(); initiatedBy = $null
                    }
                }

                $result = @{ value = @($record) }
                if ($dense -ge 0 -and $minutes -gt $dense) { $result['@odata.nextLink'] = $Uri }
                return [pscustomobject]$result
            }
        }
    }

    AfterEach {
        Remove-Item Env:\ETW_DENSE_MINUTES, Env:\ETW_REJECT -ErrorAction SilentlyContinue
        . $script:Module { Remove-Item Function:\Start-Sleep -ErrorAction SilentlyContinue }
        Install-GraphStub -Module $script:Module
    }

    # Truncation has to be DATA. A caller that recovers from it by halving the window
    # cannot branch on a warning without matching its text, and matching the text of a log
    # line is a dependency that breaks the first time somebody rewords it.
    It 'reports truncation as a flag the caller can branch on' {
        $env:ETW_DENSE_MINUTES = '0'
        $uri = '/v1.0/auditLogs/signIns?$filter=createdDateTime ge 2026-06-14T00:00:00Z and createdDateTime lt 2026-06-15T00:00:00Z'
        $flag = & $script:Module {
            param($u)
            $t = $false
            $null = Invoke-TripwireGraphRequest -Uri $u -MaxPages 1 -Truncated ([ref] $t) -WarningAction SilentlyContinue
            $t
        } $uri
        $flag | Should -BeTrue
    }

    # Assigned on every read, not only on a truncated one: a $true left over from a
    # previous call would otherwise read as this call's verdict, and the caller would
    # bisect a window it had already read in full.
    It 'clears the flag on a read that ran to the end' {
        $env:ETW_DENSE_MINUTES = '99999'
        $uri = '/v1.0/auditLogs/signIns?$filter=createdDateTime ge 2026-06-14T00:00:00Z and createdDateTime lt 2026-06-15T00:00:00Z'
        $flag = & $script:Module {
            param($u)
            $t = $true
            $null = Invoke-TripwireGraphRequest -Uri $u -MaxPages 5 -Truncated ([ref] $t)
            $t
        } $uri
        $flag | Should -BeFalse
    }

    It 'bisects a window that hits the page limit and reads both halves' {
        $env:ETW_DENSE_MINUTES = '400'
        $read = & $script:Module {
            Read-TripwireLogWindow -Path '/v1.0/auditLogs/directoryAudits' -TimeField 'activityDateTime' `
                -Since ([DateTime]::Parse('2026-06-14T00:00:00Z').ToUniversalTime()) `
                -Until ([DateTime]::Parse('2026-06-15T00:00:00Z').ToUniversalTime()) `
                -MaxPagesPerWindow 2 -WarningAction SilentlyContinue
        }
        # 1440 minutes is dense, 720 is dense, 360 is not: four windows read in full.
        $read.Complete | Should -BeTrue
        @($read.IncompleteWindows).Count | Should -Be 0
        @($read.Records).Count | Should -Be 4
        $read.WindowsRead | Should -Be 7
    }

    # Half-open windows, `ge start and lt end`. Overlapping slices double every record in
    # the overlap; slices with a gap lose every record in the gap, and the gap is invisible.
    It 'tiles the window exactly: the slices neither overlap nor leave a gap' {
        $env:ETW_DENSE_MINUTES = '400'
        $null = & $script:Module {
            Read-TripwireLogWindow -Path '/v1.0/auditLogs/directoryAudits' -TimeField 'activityDateTime' `
                -Since ([DateTime]::Parse('2026-06-14T00:00:00Z').ToUniversalTime()) `
                -Until ([DateTime]::Parse('2026-06-15T00:00:00Z').ToUniversalTime()) `
                -MaxPagesPerWindow 2 -WarningAction SilentlyContinue
        }
        $spans = [System.Collections.Generic.List[object]]::new()
        foreach ($u in (& $script:Module { @($script:TestUris) })) {
            if ($u -match '\sge\s(\S+)\sand\s\S+\slt\s([^\s&]+)') {
                $start = [DateTime]::Parse($Matches[1]).ToUniversalTime()
                $end = [DateTime]::Parse($Matches[2]).ToUniversalTime()
                if (($end - $start).TotalMinutes -eq 360) { $spans.Add([pscustomobject]@{ Start = $start; End = $end }) }
            }
        }
        $leaves = @($spans | Sort-Object Start -Unique)
        $leaves.Count | Should -Be 4
        $leaves[0].Start | Should -Be ([DateTime]::Parse('2026-06-14T00:00:00Z').ToUniversalTime())
        $leaves[3].End | Should -Be ([DateTime]::Parse('2026-06-15T00:00:00Z').ToUniversalTime())
        for ($i = 1; $i -lt $leaves.Count; $i++) {
            $leaves[$i].Start | Should -Be $leaves[$i - 1].End -Because 'a gap between two slices loses every record in it, invisibly'
        }
    }

    It 'names the windows it could not read instead of returning a partial read as a whole one' {
        $env:ETW_DENSE_MINUTES = '0'
        $read = & $script:Module {
            Read-TripwireLogWindow -Path '/v1.0/auditLogs/directoryAudits' -TimeField 'activityDateTime' `
                -Since ([DateTime]::Parse('2026-06-14T00:00:00Z').ToUniversalTime()) `
                -Until ([DateTime]::Parse('2026-06-15T00:00:00Z').ToUniversalTime()) `
                -MaxPagesPerWindow 1 -MinWindowMinutes 720 -WarningAction SilentlyContinue
        }
        $read.Complete | Should -BeFalse
        @($read.IncompleteWindows).Count | Should -Be 2
        (@($read.IncompleteWindows) -join ' ') | Should -Match '2026-06-14T00:00:00Z\.\.2026-06-14T12:00:00Z'
    }

    # Bisection is bounded, because an unbounded one turns one run into a request storm
    # against a tenant. The bound has the same obligation as the page limit it replaced:
    # whatever is still queued when it is reached is UNREAD, and every one of them is named.
    It 'names every window still queued when it stops issuing requests' {
        $env:ETW_DENSE_MINUTES = '0'
        $read = & $script:Module {
            Read-TripwireLogWindow -Path '/v1.0/auditLogs/directoryAudits' -TimeField 'activityDateTime' `
                -Since ([DateTime]::Parse('2026-06-14T00:00:00Z').ToUniversalTime()) `
                -Until ([DateTime]::Parse('2026-06-15T00:00:00Z').ToUniversalTime()) `
                -MaxPagesPerWindow 1 -MaxWindows 3 -WarningAction SilentlyContinue
        }
        $read.Complete | Should -BeFalse
        $read.WindowsRead | Should -Be 3
        # Three reads, each splitting in two: four windows are left on the queue.
        @($read.IncompleteWindows).Count | Should -Be 4
    }

    It 'refuses a window that cannot contain anything rather than reporting a complete read of it' {
        {
            & $script:Module {
                $at = [DateTime]::Parse('2026-06-14T00:00:00Z').ToUniversalTime()
                Read-TripwireLogWindow -Path '/v1.0/auditLogs/signIns' -TimeField 'createdDateTime' -Since $at -Until $at
            }
        } | Should -Throw -ExpectedMessage '*cannot contain anything*'
    }

    # The loudness is the fix. A partial read was already warned about and the warning sat
    # among the other log lines of a run that returned trips and looked successful.
    It 'reports an unread window from Watch-TripwireActivity as an ERROR, not one more log line' {
        $env:ETW_DENSE_MINUTES = '0'
        $errors = @()
        $null = Watch-TripwireActivity -Days 1 -Decoy @(New-TestDecoy) -Baseline (New-TestBaseline) `
            -MaxPagesPerWindow 1 -MinWindowMinutes 720 `
            -ErrorVariable errors -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        ($errors -join ' ') | Should -Match 'did not read its whole window'
        ($errors -join ' ') | Should -Match 'NOT in this result'
    }

    # Zero touches from a window that was never read is THE failure that looks like good
    # news, so the message cannot live inside the branch that only runs when trips exist.
    It 'says so even when the run found nothing, which is when it matters most' {
        $env:ETW_DENSE_MINUTES = '0'
        $errors = @()
        $trips = @(Watch-TripwireActivity -Days 1 `
                -Decoy @(New-TestDecoy -ObjectId 'matches-nothing' -DisplayName 'matches-nothing-either') `
                -Baseline (New-TestBaseline) -MaxPagesPerWindow 1 -MinWindowMinutes 720 `
                -ErrorVariable errors -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
        $trips.Count | Should -Be 0
        ($errors -join ' ') | Should -Match 'did not read its whole window'
    }

    It 'downgrades the error to a warning only when the operator asks for a partial view' {
        $env:ETW_DENSE_MINUTES = '0'
        $errors = @()
        $warnings = @()
        $null = Watch-TripwireActivity -Days 1 -Decoy @(New-TestDecoy) -Baseline (New-TestBaseline) `
            -MaxPagesPerWindow 1 -MinWindowMinutes 720 -AcceptPartialRead `
            -ErrorVariable errors -ErrorAction SilentlyContinue -WarningVariable warnings -WarningAction SilentlyContinue
        @($errors).Count | Should -Be 0
        ($warnings -join ' ') | Should -Match 'did not read its whole window'
    }

    It 'says nothing of the sort when it did read the whole window' {
        $env:ETW_DENSE_MINUTES = '99999'
        $errors = @()
        $null = Watch-TripwireActivity -Days 1 -Decoy @(New-TestDecoy) -Baseline (New-TestBaseline) `
            -ErrorVariable errors -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        @($errors).Count | Should -Be 0
    }
}

<#
    The sign-in side is narrowed server-side, because the decoy inventory is local and
    known. That is where the 200,000 records go away. It is also where a decoy could
    silently stop being watched, so every test here is about the filter being COMPLETE
    rather than about it being small.
#>
Describe 'The sign-in query is built from the local decoy inventory' {

    It 'names every identifier the sign-in matcher compares against' {
        $decoys = @(
            New-TestDecoy -Id 'd1' -DisplayName 'svc-one' -ObjectId 'obj-1'
            New-TestDecoy -Id 'd2' -DisplayName 'svc-two' -ObjectId 'obj-2'
        )
        $f = & $script:Module { param($d) Get-TripwireDecoyFilterGroup -Decoy $d } $decoys
        $f.Complete | Should -BeTrue
        $joined = (@($f.Groups) -join ' ')
        foreach ($expected in @('obj-1', 'obj-2', 'svc-one%40contoso.com', 'svc-two%40contoso.com', 'svc-one', 'svc-two')) {
            $joined | Should -BeLike "*$expected*" -Because "a decoy the filter does not name is a decoy that stops tripping"
        }
    }

    It 'never mixes two fields in one OR group' {
        $decoys = @(New-TestDecoy -Id 'd1' -ObjectId 'obj-1')
        $f = & $script:Module { param($d) Get-TripwireDecoyFilterGroup -Decoy $d } $decoys
        foreach ($group in $f.Groups) {
            @($group -split ' or ' | ForEach-Object { ($_ -split ' ')[0] } | Sort-Object -Unique).Count | Should -Be 1
        }
    }

    # A guest UPN contains '#'. Unescaped, it truncates the request URI at the fragment --
    # the query still succeeds, and that decoy's clause is simply not in it.
    It 'escapes a value that would otherwise cut the request URI in half' {
        $d = New-TestDecoy -Id 'd1' -ObjectId 'obj-1'
        $d.upn = 'guest_fabrikam.com#EXT#@contoso.onmicrosoft.com'
        $f = & $script:Module { param($dd) Get-TripwireDecoyFilterGroup -Decoy $dd } @($d)
        $joined = (@($f.Groups) -join ' ')
        $joined | Should -Not -Match '#EXT#'
        $joined | Should -Match '%23EXT%23'
    }

    It 'escapes an embedded quote rather than letting it close the literal' {
        $d = New-TestDecoy -Id 'd1' -ObjectId "obj'1"
        $f = & $script:Module { param($dd) Get-TripwireDecoyFilterGroup -Decoy $dd } @($d)
        (@($f.Groups) -join ' ') | Should -Match "obj%27%271"
    }

    It 'splits a large inventory into several queries rather than one Graph may refuse' {
        $decoys = @(1..20 | ForEach-Object { New-TestDecoy -Id "d$_" -DisplayName "svc-$_" -ObjectId "obj-$_" })
        $f = & $script:Module { param($d) Get-TripwireDecoyFilterGroup -Decoy $d } $decoys
        $f.Complete | Should -BeTrue
        @($f.Groups | Where-Object { $_ -like 'userId eq*' }).Count | Should -Be 2
        foreach ($group in $f.Groups) { @($group -split ' or ').Count | Should -BeLessOrEqual 15 }
    }

    # The one that matters. A decoy with no object id, no application id and no UPN cannot
    # be named in a filter, so narrowing the query would stop watching it -- with no
    # symptom at all, because a decoy that is never matched simply never trips again.
    It 'refuses to narrow the query at all when one decoy cannot be named in it' {
        $orphan = New-TestDecoy -Id 'd2' -DisplayName 'name-only'
        $orphan.objectId = ''
        $orphan.upn = ''
        $f = & $script:Module { param($d) Get-TripwireDecoyFilterGroup -Decoy $d } @((New-TestDecoy -Id 'd1'), $orphan)
        $f.Complete | Should -BeFalse
        $f.Reason | Should -Match 'name-only'
    }
}

Describe 'Narrowing the sign-in query can never cost a detection' {

    BeforeEach {
        Remove-Item Env:\ETW_REJECT -ErrorAction SilentlyContinue
        . $script:Module {
            $script:TestUris = [System.Collections.Generic.List[string]]::new()
            function Invoke-MgGraphRequest {
                param([string] $Method, [string] $Uri, $Body, $OutputType, $ErrorAction)
                $script:TestUris.Add($Uri)

                if ($env:ETW_REJECT -and $Uri -match [regex]::Escape($env:ETW_REJECT)) {
                    $ex = [System.Exception]::new('Invalid filter clause specified for property')
                    $err = [System.Management.Automation.ErrorRecord]::new($ex, 'BadRequest', 'NotSpecified', $null)
                    $err.Exception | Add-Member -NotePropertyName Response `
                        -NotePropertyValue ([pscustomobject]@{ StatusCode = 400 }) -Force
                    throw $err
                }

                if ($Uri -notmatch 'signIns') { return [pscustomobject]@{ value = @() } }
                return [pscustomobject]@{
                    value = @([pscustomobject]@{
                            id                     = 'si-1'
                            createdDateTime        = '2026-06-15T14:00:00Z'
                            userId                 = 'obj-decoy-1'
                            userPrincipalName      = 'svc-decoy@contoso.com'
                            userDisplayName        = 'svc-decoy'
                            appId                  = 'app-unrelated'
                            appDisplayName         = 'Office 365 Exchange Online'
                            ipAddress              = '203.0.113.5'
                            autonomousSystemNumber = '7922'
                            status                 = [pscustomobject]@{ errorCode = 0 }
                            location               = [pscustomobject]@{ countryOrRegion = 'US' }
                        })
                }
            }
        }
    }

    AfterEach {
        Remove-Item Env:\ETW_REJECT -ErrorAction SilentlyContinue
        Install-GraphStub -Module $script:Module
    }

    It 'asks Graph for the decoy identities instead of the whole sign-in log' {
        $null = Watch-TripwireActivity -Days 1 -Decoy @(New-TestDecoy) -Baseline (New-TestBaseline) `
            -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $signInUris = @((& $script:Module { @($script:TestUris) }) | Where-Object { $_ -match 'signIns' })
        @($signInUris).Count | Should -BeGreaterThan 0
        ($signInUris -join ' ') | Should -Match 'userId eq'
    }

    It 'finds the touch through the narrowed query' {
        $trips = @(Watch-TripwireActivity -Days 1 -Decoy @(New-TestDecoy) -Baseline (New-TestBaseline) `
                -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
        @($trips | Where-Object { $_.Touch.source -eq 'SignInLog' }).Count | Should -Be 1
    }

    # One record can satisfy two groups -- its userId and its UPN are both decoy keys --
    # and the same record twice is the same incident reported twice.
    It 'does not report the same record once per clause group that matched it' {
        $trips = @(Watch-TripwireActivity -Days 1 -Decoy @(New-TestDecoy) -Baseline (New-TestBaseline) `
                -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
        @($trips | Where-Object { $_.TouchId -eq 'si-1' }).Count | Should -Be 1
    }

    # Narrowing is an optimisation. An optimisation that Graph refuses must not take the
    # detection with it: the run falls back to the whole window and matches locally.
    It 'falls back to the whole window when Graph refuses the filter, and STILL finds the touch' {
        $env:ETW_REJECT = 'userId eq'
        $warnings = @()
        $trips = @(Watch-TripwireActivity -Days 1 -Decoy @(New-TestDecoy) -Baseline (New-TestBaseline) `
                -ErrorAction SilentlyContinue -WarningVariable warnings -WarningAction SilentlyContinue)
        @($trips | Where-Object { $_.Touch.source -eq 'SignInLog' }).Count | Should -Be 1
        ($warnings -join ' ') | Should -Match 'Falling back'
    }

    It 'reads the whole window, unnarrowed, when one decoy cannot be named in a filter' {
        $orphan = New-TestDecoy -Id 'd2' -DisplayName 'name-only'
        $orphan.objectId = ''
        $orphan.upn = ''
        $warnings = @()
        $null = Watch-TripwireActivity -Days 1 -Decoy @((New-TestDecoy), $orphan) -Baseline (New-TestBaseline) `
            -ErrorAction SilentlyContinue -WarningVariable warnings -WarningAction SilentlyContinue
        $signInUris = @((& $script:Module { @($script:TestUris) }) | Where-Object { $_ -match 'signIns' })
        ($signInUris -join ' ') | Should -Not -Match 'userId eq'
        ($warnings -join ' ') | Should -Match 'cannot be narrowed server-side'
    }

    # Directory audits are the source that CANNOT be narrowed: Graph's filter over
    # targetResources does not express "any of these N objects". A filter that pretended
    # to would drop a decoy, so this one stays a time-window read for ever.
    It 'never tries to name a decoy in the directory-audit query' {
        $null = Watch-TripwireActivity -Days 1 -Decoy @(New-TestDecoy) -Baseline (New-TestBaseline) `
            -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $auditUris = @((& $script:Module { @($script:TestUris) }) | Where-Object { $_ -match 'directoryAudits' })
        @($auditUris).Count | Should -BeGreaterThan 0
        ($auditUris -join ' ') | Should -Not -Match 'targetResources'
        ($auditUris -join ' ') | Should -Match 'activityDateTime ge'
    }
}

Describe 'The baseline announces its own age when it is loaded' {

    BeforeAll {
        function script:New-BaselineFile([string] $GeneratedAt) {
            $path = Join-Path ([System.IO.Path]::GetTempPath()) ("baseline-{0}.json" -f [Guid]::NewGuid())
            $b = New-TestBaseline
            $b.generatedAt = $GeneratedAt
            $b | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding utf8
            return $path
        }
    }

    # generatedAt has been written into every baseline this module ever produced and
    # nothing read it, so a baseline from six months ago was used in silence.
    It 'says a baseline past the stale age will have its signals withheld' {
        $path = script:New-BaselineFile '2020-01-01T00:00:00Z'
        $warnings = @()
        $loaded = Get-TripwireBaseline -Path $path -WarningVariable warnings -WarningAction SilentlyContinue
        $loaded | Should -Not -BeNullOrEmpty -Because 'a stale baseline is still returned; it is the operator who decides'
        ($warnings -join ' ') | Should -Match 'WITHHELD'
        Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
    }

    It 'gives notice before that, while the baseline is still being used' {
        $path = script:New-BaselineFile ([DateTime]::UtcNow.AddDays(-20).ToString('o'))
        $warnings = @()
        $null = Get-TripwireBaseline -Path $path -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join ' ') | Should -Match 'day\(s\) old'
        ($warnings -join ' ') | Should -Not -Match 'WITHHELD'
        Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
    }

    It 'says nothing about a baseline that is current' {
        $path = script:New-BaselineFile ([DateTime]::UtcNow.AddDays(-1).ToString('o'))
        $warnings = @()
        $null = Get-TripwireBaseline -Path $path -WarningVariable warnings -WarningAction SilentlyContinue
        @($warnings).Count | Should -Be 0
        Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
    }

    # The shipped fixtures are frozen in 2026-06 on purpose, so their age against today's
    # clock is a fact about the calendar and not about a tenant. The exception is narrow by
    # design and this test is what keeps it narrow: it must not spread to real baselines.
    It 'does not nag about the shipped demo fixtures' {
        $warnings = @()
        $null = Get-TripwireBaseline -Demo -WarningVariable warnings -WarningAction SilentlyContinue
        @($warnings).Count | Should -Be 0
    }
}
