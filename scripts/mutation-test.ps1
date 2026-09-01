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
    [string] $WorkRoot = (Join-Path ([System.IO.Path]::GetTempPath()) "entra-tripwire-mutation-$([Guid]::NewGuid().ToString('n').Substring(0,8))")
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
        From = '| Sort-Object -Unique).Count'; To = ').Count'
        Defect = 'Fan-out counts events instead of distinct decoys: one decoy retried looks like a sweep.'
    }
    @{ Name = 'containment-band-gate'; File = 'src/EntraTripwire/Public/Invoke-TripwireContainment.ps1'
        From = "if (`$Trip.Band -ne 'High')"; To = "if (`$Trip.Band -eq 'High')"
        Defect = 'Containment refuses High trips and accepts everything else.'
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
    Write-Host ("Mutants: {0}   Killed: {1}   Survived: {2}   Not applied: {3}" -f $results.Count, $killed, $survived, $notApplied)

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
