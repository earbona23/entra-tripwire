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
