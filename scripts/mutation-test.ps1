#Requires -Version 7.2
<#
.SYNOPSIS
    Mutation testing for the scoring engine and the safety guards.

.DESCRIPTION
    A green suite proves the tests ran. It does not prove they would notice if the code
    were wrong. This harness answers that directly: it introduces one deliberate defect at
    a time and requires the suite to go red. A mutant that survives is a hole in the tests,
    named and located.

    Three outcomes, not two:

      Killed       the suite went red. The tests defend this line.
      SURVIVED     the suite stayed green with a real defect in place. A hole.
      NOT APPLIED  the edit did not change the file at all.

    That third outcome is the reason this script verifies the file content before and after
    every edit. A mutation that fails to apply produces a green run that is indistinguishable
    from a surviving mutant, and it is indistinguishable in the direction that flatters the
    tests: the harness would report "killed" for a defect it never introduced. Every entry
    below is checked, and a mutation that does not apply fails the run.

    The whole exercise runs in a throwaway copy of src/ and tests/, so an interrupted run
    cannot leave a mutated file in the working tree.

.EXAMPLE
    pwsh ./scripts/mutation-test.ps1
#>
[CmdletBinding()]
param(
    [string] $WorkRoot = (Join-Path ([System.IO.Path]::GetTempPath()) "entra-tripwire-mutation-$([Guid]::NewGuid().ToString('n').Substring(0,8))"),

    # Run only the named mutants. Every mutant still has to be applied and killed before a
    # change ships, and CI passes nothing here, so the gate is unchanged -- this is for
    # working on one area without paying for the whole set, and for finishing a run that
    # was interrupted. A filtered run says so in its summary, because a green "4 of 4
    # killed" that reads like the whole suite is the same lie as a truncated log read.
    [string[]] $Only = @()
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

$mutants = @(
    @{ Name = 'purity-weight'; File = 'src/EntraTripwire/Public/Get-TripwirePolicy.ps1'
        From = 'DecoyPurity      = 0.40'; To = 'DecoyPurity      = 0.25'
        Defect = 'Decoy purity stops being the dominant signal.'
    }
    @{ Name = 'high-threshold'; File = 'src/EntraTripwire/Public/Get-TripwirePolicy.ps1'
        From = 'High   = 75'; To = 'High   = 65'
        Defect = 'The containment band opens ten points early.'
    }
    @{ Name = 'pristine-purity-raw'; File = 'src/EntraTripwire/Public/Get-TripwirePolicy.ps1'
        From = '@{ MaxUses = 0; Raw = 1.00 }'; To = '@{ MaxUses = 0; Raw = 0.50 }'
        Defect = 'A never-used decoy scores half strength.'
    }
    @{ Name = 'fanout-top-tier'; File = 'src/EntraTripwire/Public/Get-TripwirePolicy.ps1'
        From = '@{ MinDecoys = 4; Raw = 1.00 }'; To = '@{ MinDecoys = 4; Raw = 0.60 }'
        Defect = 'A four-decoy sweep scores no higher than a two-decoy one.'
    }
    @{ Name = 'unseen-country-raw'; File = 'src/EntraTripwire/Public/Get-TripwirePolicy.ps1'
        From = 'UnseenCountry = 1.00'; To = 'UnseenCountry = 0.50'
        Defect = 'A country the tenant has never used scores half strength.'
    }
    @{ Name = 'provisioning-grace'; File = 'src/EntraTripwire/Public/Get-TripwirePolicy.ps1'
        From = 'ProvisioningGraceMinutes = 15'; To = 'ProvisioningGraceMinutes = 0'
        Defect = 'The planting window closes instantly, so every deployment alerts on itself.'
    }
    @{ Name = 'fanout-boundary'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = 'if ($DistinctDecoyCount -ge $tier.MinDecoys)'; To = 'if ($DistinctDecoyCount -gt $tier.MinDecoys)'
        Defect = 'Off-by-one: the fan-out tiers are reached one decoy late.'
    }
    @{ Name = 'impossible-travel-direction'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = 'if ($kph -gt $Policy.ImpossibleTravelKph)'; To = 'if ($kph -lt $Policy.ImpossibleTravelKph)'
        Defect = 'Impossible travel fires on normal journeys and not on impossible ones.'
    }
    @{ Name = 'offhours-inverted'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = '$raw = 1.0 - $density'; To = '$raw = $density'
        Defect = 'The busiest hour becomes the suspicious one.'
    }
    @{ Name = 'allowlist-ignored'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = 'return "Actor $actorId is on the tenant suppression allowlist."'
        To = '$null = $actorId'
        Defect = 'The operator allowlist stops suppressing anything.'
    }
    @{ Name = 'provisioning-window-inverted'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = '$sincePlant -le $Policy.ProvisioningGraceMinutes'; To = '$sincePlant -ge $Policy.ProvisioningGraceMinutes'
        Defect = 'Provisioning grace suppresses everything EXCEPT the provisioning window.'
    }
    @{ Name = 'origin-withheld-becomes-scored'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = @'
        return New-TripwireSignal -Name 'OriginAnomaly' -Weight $weight -Available $false `
            -Rationale 'No tenant baseline of sign-in origins, so "unusual origin" has no meaning yet. Run Get-TripwireBaseline first.'
'@
        To = @'
        return New-TripwireSignal -Name 'OriginAnomaly' -Weight $weight -Available $true `
            -Rationale 'No tenant baseline of sign-in origins, so "unusual origin" has no meaning yet. Run Get-TripwireBaseline first.'
'@
        Defect = 'A signal that could not be evaluated reports itself as evaluated-and-clean.'
    }
    @{ Name = 'withheld-still-counts'; File = 'src/EntraTripwire/Private/New-TripwireSignal.ps1'
        From = '$effective = if ($Available) { $Raw } else { 0.0 }'; To = '$effective = $Raw'
        Defect = 'An unavailable signal contributes its raw value anyway.'
    }
    @{ Name = 'band-boundary'; File = 'src/EntraTripwire/Public/Measure-TripwireConfidence.ps1'
        From = 'if ($confidence -ge $Policy.Threshold.High)'; To = 'if ($confidence -gt $Policy.Threshold.High)'
        Defect = 'A score exactly on the threshold falls out of the High band.'
    }
    @{ Name = 'fanout-counts-events'; File = 'src/EntraTripwire/Public/Invoke-TripwireAnalysis.ps1'
        From = '[void] $distinct.Add($sorted[$j].DecoyId)'; To = '[void] $distinct.Add("$($sorted[$j].DecoyId)-$j")'
        Defect = 'Fan-out counts events instead of distinct decoys: one decoy retried looks like a sweep.'
    }
    @{ Name = 'correlation-window-ignored'; File = 'src/EntraTripwire/Public/Invoke-TripwireAnalysis.ps1'
        From = 'while (($hi + 1) -lt $sorted.Count -and ($sorted[$hi + 1].Ticks - $centre) -le $windowTicks) { $hi++ }'
        To = 'while (($hi + 1) -lt $sorted.Count) { $hi++ }'
        Defect = 'The correlation window stops bounding anything: every touch an actor ever made counts as fan-out.'
    }
    @{ Name = 'suppression-unplaceable-time'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = '$plantedAt = if ($null -ne $Decoy) { ConvertTo-TripwireUtcOrNull $Decoy.plantedAt } else { $null }'
        To = '$plantedAt = if ($null -ne $Decoy) { ConvertTo-TripwireUtc $Decoy.plantedAt } else { $null }'
        Defect = 'A hand-edited plantedAt that is not a date raises a parse error from inside the suppression rule and abandons the run.'
    }
    @{ Name = 'collection-rejects-undated'; File = 'src/EntraTripwire/Private/ConvertTo-TripwireTouch.ps1'
        From = 'timestamp = ConvertTo-TripwireUtcOrNull $Record.createdDateTime'
        To = 'timestamp = ConvertTo-TripwireUtc $Record.createdDateTime'
        Defect = 'One sign-in record without a createdDateTime raises a parse error and abandons the whole collection run.'
    }
    @{ Name = 'policy-integrity-off'; File = 'src/EntraTripwire/Public/Get-TripwirePolicy.ps1'
        From = 'if ($Override) { Assert-TripwirePolicy -Policy $result }'; To = '$null = $Override'
        Defect = 'An incomplete policy is accepted again: a missing High threshold bands every trip High, because 50 -ge $null is true.'
    }
    @{ Name = 'offhours-undated-scored'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = @'
    $at = ConvertTo-TripwireUtcOrNull $Touch.timestamp
    if ($null -eq $at) {
'@
        To = @'
    $at = ConvertTo-TripwireUtcOrNull $Touch.timestamp
    if ($false) {
'@
        Defect = 'A record with no timestamp is scored for off-hours anyway instead of withholding the signal.'
    }
    # The two licence mutants moved with the verifier: entitlement is decided in
    # EntraTripwirePro now, and its repository carries the mutants for it.
    @{ Name = 'provider-assumed-present'; File = 'src/EntraTripwire/Private/Provider.ps1'
        From = "    try { return (@((Get-TripwireProvider).Capabilities) -contains `$Feature) }"
        To = '    try { return $true }'
        Defect = 'Every paid capability reads as installed, so containment executes with no module behind it.'
    }
    @{ Name = 'provider-ignores-empty-capabilities'; File = 'src/EntraTripwire/Private/Provider.ps1'
        From = '        Available    = ($caps.Count -gt 0)'
        To = '        Available    = $true'
        Defect = 'A paid module that entitles nothing, which is what a lapsed licence looks like, reads as entitled.'
    }
    @{ Name = 'containment-trusts-the-log'; File = 'src/EntraTripwire/Public/Invoke-TripwireContainment.ps1'
        From = '            $decoyObjectId = [string]$Trip.DecoyObjectId'
        To = '            $decoyObjectId = [string]$Trip.Touch.actor.id'
        Defect = 'Containment disables the principal named in the log record instead of the decoy recorded in the local inventory.'
    }
    @{ Name = 'containment-band-gate'; File = 'src/EntraTripwire/Public/Invoke-TripwireContainment.ps1'
        From = "if (`$Trip.Band -ne 'High')"; To = "if (`$Trip.Band -eq 'High')"
        Defect = 'Containment refuses High trips and accepts everything else.'
    }
    @{ Name = 'lookback-window-unchecked'; File = 'src/EntraTripwire/Public/Watch-TripwireActivity.ps1'
        From = '[ValidateRange(1, 365)] [int] $Days = 1'; To = '[int] $Days = 1'
        Defect = 'A zero or negative lookback is accepted again, putting the Graph filter in the future and reporting a blind run as a quiet tenant.'
    }
    @{ Name = 'orphan-decoy-silent'; File = 'src/EntraTripwire/Public/New-TripwireDecoy.ps1'
        From = "    if (-not `$RegisterOnly -and [string]::IsNullOrWhiteSpace([string]`$record['objectId'])) {"
        To = '    if ($false) {'
        Defect = 'A decoy planted without an object id is recorded as healthy, though it can neither be removed nor contained.'
    }
    @{ Name = 'purity-count-unchecked'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = "        if (-not [int]::TryParse([string]`$Decoy.legitimateUseCount, [ref] `$parsed)) {"
        To = '        if ($false) {'
        Defect = 'A hand-edited legitimateUseCount that is not a number crashes the dominant signal again.'
    }
    @{ Name = 'truncation-silent'; File = 'src/EntraTripwire/Private/Invoke-TripwireGraphRequest.ps1'
        From = @'
Write-TripwireLog -Level 'Warn' -Message "Stopped after $MaxPages pages; results are TRUNCATED. Narrow the time window or raise -MaxPages."
'@
        To = '$null = $MaxPages'
        Defect = 'A read that stopped at the page limit is reported as a complete one.'
    }
    @{ Name = 'read-failure-swallowed'; File = 'src/EntraTripwire/Private/Invoke-TripwireGraphRequest.ps1'
        From = @'
throw "Graph GET failed for '$next': $($_.Exception.Message)"
'@
        To = 'return $results.ToArray()'
        Defect = 'An exhausted read returns an empty set, so a failed log read is indistinguishable from a quiet tenant.'
    }
    @{ Name = 'retries-unretryable'; File = 'src/EntraTripwire/Private/Invoke-TripwireGraphRequest.ps1'
        From = 'if (($status -eq 429 -or $status -ge 500) -and $attempt -le $MaxRetry) {'
        To = 'if ($attempt -le $MaxRetry) {'
        Defect = 'A 403 from a missing permission is retried as if it were throttling, hiding a configuration error behind a delay.'
    }
    # ---- Collection: the page limit, the windowed read, and the inventory-driven filter.
    @{ Name = 'truncation-not-signalled'; File = 'src/EntraTripwire/Private/Invoke-TripwireGraphRequest.ps1'
        From = 'if ($null -ne $Truncated) { $Truncated.Value = [bool] $next }'
        To = 'if ($null -ne $Truncated) { $Truncated.Value = $false }'
        Defect = 'A read that stopped at the page limit tells its caller it finished, so the unread part of the window is never recovered.'
    }
    @{ Name = 'window-not-bisected'; File = 'src/EntraTripwire/Private/Invoke-TripwireGraphRequest.ps1'
        From = 'if ($span.TotalMinutes -gt $MinWindowMinutes -and $mid -gt $window.Start -and $mid -lt $window.End) {'
        To = 'if ($false) {'
        Defect = 'A window too dense to read in one go is given up on instead of split, so its records stay out of the run.'
    }
    @{ Name = 'unread-window-not-named'; File = 'src/EntraTripwire/Private/Invoke-TripwireGraphRequest.ps1'
        From = '        $incomplete.Add((& $label $window))'
        To = '        $null = $window'
        Defect = 'A window that could not be read is dropped from the accounting, so a partial read reports itself as a whole one.'
    }
    @{ Name = 'queued-windows-discarded'; File = 'src/EntraTripwire/Private/Invoke-TripwireGraphRequest.ps1'
        From = 'while ($pending.Count -gt 0) { $incomplete.Add((& $label $pending.Pop())) }'
        To = '$pending.Clear()'
        Defect = 'The windows still queued when the request ceiling is reached are thrown away instead of reported, so the ceiling becomes a silent cut-off of its own.'
    }
    @{ Name = 'partial-read-not-reported'; File = 'src/EntraTripwire/Public/Watch-TripwireActivity.ps1'
        From = "            Write-Error -Message `$message -Category LimitsExceeded -ErrorId 'TripwireIncompleteRead'"
        To = '            $null = $message'
        Defect = 'An incompletely read window is announced quietly instead of as an error, which is how a blind run passes for a quiet tenant.'
    }
    @{ Name = 'signin-filter-drops-a-decoy'; File = 'src/EntraTripwire/Private/Invoke-TripwireGraphRequest.ps1'
        From = 'Complete = ($uncovered.Count -eq 0 -and $groups.Count -gt 0)'
        To = 'Complete = $true'
        Defect = 'A decoy that cannot be named in the server-side filter is quietly left out of the query, so it stops tripping with no symptom at all.'
    }
    @{ Name = 'signin-filter-unescaped'; File = 'src/EntraTripwire/Private/Invoke-TripwireGraphRequest.ps1'
        From = '"$field eq ''$([Uri]::EscapeDataString($_.Replace("''", "''''")))''"'
        To = '"$field eq ''$_''"'
        Defect = 'A guest UPN containing # truncates the request URI at the fragment: the query still succeeds and that decoy is simply not in it.'
    }
    @{ Name = 'filter-failure-not-recovered'; File = 'src/EntraTripwire/Public/Watch-TripwireActivity.ps1'
        From = '                $signIns = $null
                Write-TripwireLog -Level ''Warn'' -Message "The targeted sign-in query failed'
        To = '                $signIns = @()
                Write-TripwireLog -Level ''Warn'' -Message "The targeted sign-in query failed'
        Defect = 'A filter Graph refuses leaves the sign-in log unread instead of falling back to the whole window, so the whole source goes silent.'
    }

    # ---- Baseline freshness: generatedAt was written by every version and read by none.
    @{ Name = 'baseline-staleness-ignored'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = '    $stale = ($age -gt $staleAge)'
        To = '    $stale = $false'
        Defect = 'A baseline from six months ago is believed, so "unusual country" and "outside working hours" are scored against a tenant that no longer exists.'
    }
    @{ Name = 'baseline-age-unknown-assumed-fresh'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = '        return & $verdict $false $true $true $null (
            "the baseline records generatedAt as'
        To = '        return & $verdict $false $false $false $null (
            "the baseline records generatedAt as'
        Defect = 'A baseline whose age cannot be established is treated as a fresh one. An age nobody can establish is not freshness.'
    }
    @{ Name = 'freshness-limits-null-waved-through'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = '    if ($null -eq $warnAge -or $null -eq $staleAge) {'
        To = '    if ($false) {'
        Defect = 'A policy that lost its freshness limits decides the question by $null comparison instead of being refused, and `14 -gt $null` is $true.'
    }
    @{ Name = 'baseline-load-age-silent'; File = 'src/EntraTripwire/Public/Get-TripwireBaseline.ps1'
        From = '        elseif (-not $Demo) {'
        To = '        elseif ($false) {'
        Defect = 'Loading a six-month-old baseline says nothing, which is how it came to be used in silence in the first place.'
    }

    # ---- Numbers read out of files an operator is told to edit by hand.
    @{ Name = 'totalsignins-unchecked'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = '    $total = ConvertTo-TripwireNumberOrNull $declaredTotal'
        To = '    $total = [int]$declaredTotal'
        Defect = 'A corrected totalSignIns written as a word throws from inside the origin signal and abandons every other trip in the batch.'
    }
    @{ Name = 'histogram-bucket-unchecked'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = '        $parsed = ConvertTo-TripwireNumberOrNull $bucket'
        To = '        $parsed = [double]$bucket'
        Defect = 'One hour-histogram bucket that is not a number throws from the off-hours signal, per touch, and takes the run down.'
    }
    @{ Name = 'unreadable-count-scored-as-unseen'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = '        if ($null -ne $declared -and $null -eq $seen) {'
        To = '        if ($false) {'
        Defect = 'A baseline country count that is corrupt is scored as a country never seen, which manufactures a full origin anomaly out of a typo.'
    }
    @{ Name = 'coordinates-unchecked'; File = 'src/EntraTripwire/Private/Measure-TripwireSignal.ps1'
        From = '            -Lat1 (ConvertTo-TripwireNumberOrNull $lastSeen.latitude) `'
        To = '            -Lat1 $lastSeen.latitude `'
        Defect = 'A hand-edited latitude throws during parameter binding, before the distance function can guard anything.'
    }
    @{ Name = 'write-body-unchecked'; File = 'src/EntraTripwire/Private/Invoke-TripwireGraphWrite.ps1'
        From = 'if ([string]$Body[$k] -ne [string]$expected[$k]) { $mismatch = $true; break }'
        To = '$null = $k'
        Defect = 'The write allowlist stops checking PATCH bodies, so accountEnabled=true is permitted.'
    }
)

function Invoke-SuiteInDirectory {
    param([Parameter(Mandatory)] [string] $Root)

    $script = @"
`$env:ENTRATRIPWIRE_CONFIG_DIR = '$(Join-Path $Root 'config')'
Import-Module Pester -MinimumVersion 5.0.0
`$c = New-PesterConfiguration
`$c.Run.Path = '$(Join-Path $Root 'tests')'
`$c.Run.PassThru = `$true
`$c.Output.Verbosity = 'None'
`$r = Invoke-Pester -Configuration `$c
"PASSED=`$(`$r.PassedCount) FAILED=`$(`$r.FailedCount)"
"@
    $out = pwsh -NoProfile -Command $script 2>&1
    $line = @($out | Where-Object { $_ -match '^PASSED=\d+ FAILED=\d+$' })[-1]
    if (-not $line) {
        return [pscustomobject]@{ Passed = 0; Failed = -1; Raw = ($out -join "`n") }
    }
    if ($line -match '^PASSED=(\d+) FAILED=(\d+)$') {
        return [pscustomobject]@{ Passed = [int]$Matches[1]; Failed = [int]$Matches[2]; Raw = '' }
    }
}

# One comma-separated string is accepted as well as an array, because `pwsh -File` hands
# every argument over as a literal string and `-Only a,b` arrives as the single element
# 'a,b'. Without this, the guard below correctly refuses a list that looks perfectly valid.
$Only = @($Only | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

if ($Only.Count -gt 0) {
    $known = @($mutants | ForEach-Object { $_.Name })
    $unknown = @($Only | Where-Object { $known -notcontains $_ })
    if ($unknown.Count -gt 0) {
        # A name that matches nothing would otherwise silently narrow the run to fewer
        # mutants than asked for, and report success for the ones it did run.
        throw "No mutant is named: $($unknown -join ', '). Known mutants: $($known -join ', ')."
    }
    $mutants = @($mutants | Where-Object { $Only -contains $_.Name })
    Write-Host "FILTERED RUN: $($mutants.Count) of $($known.Count) mutants ($($Only -join ', '))." -ForegroundColor Yellow
}

Write-Host "Staging a throwaway copy in $WorkRoot" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
Copy-Item -Path (Join-Path $repo 'src') -Destination $WorkRoot -Recurse -Force
Copy-Item -Path (Join-Path $repo 'tests') -Destination $WorkRoot -Recurse -Force

try {
    Write-Host 'Baseline run (must be green, or nothing below means anything)...' -ForegroundColor Cyan
    $baseline = Invoke-SuiteInDirectory -Root $WorkRoot
    if ($baseline.Failed -ne 0) {
        Write-Host $baseline.Raw
        throw "The baseline suite is not green ($($baseline.Failed) failed). Fix that before measuring mutation."
    }
    Write-Host "Baseline: $($baseline.Passed) passed, 0 failed." -ForegroundColor Green
    Write-Host ''

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($m in $mutants) {
        $target = Join-Path $WorkRoot $m.File
        $pristine = Get-Content -LiteralPath $target -Raw

        if (-not $pristine.Contains($m.From)) {
            $results.Add([pscustomobject]@{ Name = $m.Name; Outcome = 'NOT APPLIED'; Detail = 'the pattern is not present in the file'; Defect = $m.Defect })
            Write-Host ("  {0,-32} NOT APPLIED (pattern absent)" -f $m.Name) -ForegroundColor Red
            continue
        }

        $mutated = $pristine.Replace($m.From, $m.To)
        if ($mutated -eq $pristine) {
            $results.Add([pscustomobject]@{ Name = $m.Name; Outcome = 'NOT APPLIED'; Detail = 'the replacement is identical to the original'; Defect = $m.Defect })
            Write-Host ("  {0,-32} NOT APPLIED (no-op edit)" -f $m.Name) -ForegroundColor Red
            continue
        }

        Set-Content -LiteralPath $target -Value $mutated -NoNewline
        try {
            # Re-read from disk. The check above proves the STRING differs; this proves the
            # FILE does. A failed write would otherwise be reported as a killed mutant.
            $onDisk = Get-Content -LiteralPath $target -Raw
            if ($onDisk -eq $pristine) {
                $results.Add([pscustomobject]@{ Name = $m.Name; Outcome = 'NOT APPLIED'; Detail = 'the file on disk is unchanged'; Defect = $m.Defect })
                Write-Host ("  {0,-32} NOT APPLIED (write did not stick)" -f $m.Name) -ForegroundColor Red
                continue
            }

            $run = Invoke-SuiteInDirectory -Root $WorkRoot
            if ($run.Failed -gt 0) {
                $results.Add([pscustomobject]@{ Name = $m.Name; Outcome = 'Killed'; Detail = "$($run.Failed) test(s) went red"; Defect = $m.Defect })
                Write-Host ("  {0,-32} killed by {1} test(s)" -f $m.Name, $run.Failed) -ForegroundColor Green
            }
            else {
                $results.Add([pscustomobject]@{ Name = $m.Name; Outcome = 'SURVIVED'; Detail = 'the suite stayed green'; Defect = $m.Defect })
                Write-Host ("  {0,-32} SURVIVED -- {1}" -f $m.Name, $m.Defect) -ForegroundColor Red
            }
        }
        finally {
            Set-Content -LiteralPath $target -Value $pristine -NoNewline
        }
    }

    Write-Host ''
    $killed = @($results | Where-Object Outcome -eq 'Killed').Count
    $survived = @($results | Where-Object Outcome -eq 'SURVIVED').Count
    $notApplied = @($results | Where-Object Outcome -eq 'NOT APPLIED').Count

    $results | Format-Table Name, Outcome, Defect -AutoSize -Wrap | Out-String | Write-Host
    $scope = if ($Only.Count -gt 0) { ' (FILTERED RUN -- not the whole set)' } else { '' }
    Write-Host ("Mutants: {0}   Killed: {1}   Survived: {2}   Not applied: {3}{4}" -f $results.Count, $killed, $survived, $notApplied, $scope)

    if ($survived -gt 0 -or $notApplied -gt 0) {
        Write-Host 'Mutation testing FAILED.' -ForegroundColor Red
        exit 1
    }
    Write-Host 'Every mutant was applied and killed.' -ForegroundColor Green
    exit 0
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
