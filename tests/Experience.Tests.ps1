#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The first five minutes.

    Everything in this file defends a property of the experience rather than of the engine:
    that a guided run touches no tenant unless a human said so, that a gap is reported as a
    sentence with a command rather than as an exception, that the narration can be captured
    and silenced because it is on a stream and not on the host, and that the verdict the
    console prints is the one the report prints.

    The three commands added for that experience -- Start-EntraTripwire,
    Test-TripwireReadiness and Get-TripwireSummary -- are invoked inside the module's own
    session state, which is how this suite already reaches ConvertTo-TripwireHtmlReport and
    Get-TripwireWritePermit. They are exported by the loader but are NOT yet listed in the
    manifest's FunctionsToExport, so importing the .psd1 does not surface them; see the
    note on the public-surface test below.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'EntraTripwire'
    Import-Module (Join-Path $script:SourceRoot 'EntraTripwire.psd1') -Force
    $script:Module = Get-Module EntraTripwire
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Files = @(Get-ChildItem -Path $script:SourceRoot -Filter '*.ps1' -Recurse -File)

    # Colour is cosmetic and would otherwise wrap every asserted string in escapes.
    $script:PreviousNoColor = $env:NO_COLOR
    $env:NO_COLOR = '1'
}

AfterAll {
    $env:NO_COLOR = $script:PreviousNoColor
}

Describe 'The guided run, against the fixtures' {

    BeforeAll {
        $script:ReportPath = Join-Path ([System.IO.Path]::GetTempPath()) ("guided-{0}.html" -f [Guid]::NewGuid())
        Install-GraphStub -Module $script:Module
        Clear-GraphStubCall -Module $script:Module
        $script:Notes = @()
        $script:Run = & $script:Module {
            param($p)
            Start-EntraTripwire -Demo -NonInteractive -ReportPath $p `
                -InformationAction SilentlyContinue -InformationVariable notes
            $script:LastNotes = $notes
        } $script:ReportPath
        $script:Notes = @(& $script:Module { $script:LastNotes })
    }

    AfterAll {
        Remove-Item -LiteralPath $script:ReportPath -ErrorAction SilentlyContinue
    }

    It 'goes from nothing to a scored report in one command' {
        $script:Run.Mode | Should -Be 'Demo'
        @($script:Run.Trips).Count | Should -Be 9
        $script:Run.ReportPath | Should -Be $script:ReportPath
        Test-Path -LiteralPath $script:ReportPath | Should -BeTrue
    }

    It 'contacts no tenant: not one Graph call was issued' {
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
    }

    It 'never loads the Graph SDK, so the demo works on a machine that has none' {
        Get-Module -Name 'Microsoft.Graph.Authentication' | Should -BeNullOrEmpty
    }

    It 'carries the same verdict the report carries' {
        $script:Run.Summary.High | Should -Be 1
        $script:Run.Summary.Total | Should -Be 9
        # Compared against the encoded form: the report escapes everything it renders, so
        # the day a verdict gains an apostrophe this test must still be comparing the same
        # sentence rather than failing on &#39;.
        $html = Get-Content -LiteralPath $script:ReportPath -Raw
        $encoded = [System.Net.WebUtility]::HtmlEncode($script:Run.Summary.Verdict)
        $html | Should -BeLike "*$encoded*"
    }

    It 'narrates every step on the information stream, where it can be captured or silenced' {
        ($script:Notes -join "`n") | Should -Match '\[1/5\] Readiness'
        ($script:Notes -join "`n") | Should -Match '\[5/5\] Report'
        ($script:Notes -join "`n") | Should -Match 'What to do next'
    }

    It 'says which commands to run next, not just what it found' {
        ($script:Notes -join "`n") | Should -Match 'Invoke-TripwireContainment'
    }

    It 'tells the reader the demo needed none of the tenant-side checks' {
        ($script:Notes -join "`n") | Should -Match 'Demo mode needs none of the tenant-side checks'
    }

    It 'asks nothing at all, which is the only reason this test can finish' {
        # A Read-Host reached in a non-interactive run would block this suite rather than
        # fail it. The assertion is the completed run above; this records why.
        $script:Run | Should -Not -BeNullOrEmpty
    }
}

Describe 'A guided run cannot write to a tenant without being asked' {

    It 'refuses to choose a target when it cannot ask' {
        { & $script:Module { Start-EntraTripwire -NonInteractive -InformationAction SilentlyContinue } } |
            Should -Throw -ExpectedMessage '*pass -TenantId*or -Demo*'
    }

    It 'plants nothing: the only write path is behind an interactive question' {
        # The source is read rather than the code run, because the claim is about a path
        # that must not exist: there is exactly one New-TripwireDecoy call in the guided
        # run and it sits inside the interactive branch, under ShouldProcess.
        $src = Get-Content -LiteralPath (Join-Path $script:SourceRoot 'Public/Start-EntraTripwire.ps1') -Raw
        @([regex]::Matches($src, '\$planted = New-TripwireDecoy')).Count | Should -Be 1
        $src | Should -Match '\$PSCmdlet\.ShouldProcess'
        $src | Should -Not -Match 'Invoke-TripwireContainment\s+-Execute'
    }
}

Describe 'Readiness answers the first-run questions before they become exceptions' {

    BeforeAll {
        Install-GraphStub -Module $script:Module
        Clear-GraphStubCall -Module $script:Module
        $script:Checks = @(& $script:Module { Test-TripwireReadiness })
    }

    It 'reaches no tenant to answer them' {
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
    }

    It 'says of every check who needs it, so a demo machine is not told it is broken' {
        $script:Checks.Count | Should -BeGreaterThan 4
        foreach ($c in $script:Checks) {
            $c.NeededFor | Should -BeIn @('Any run', 'A real tenant', 'Pro features')
            $c.PSObject.TypeNames | Should -Contain 'EntraTripwire.ReadinessCheck'
        }
    }

    It 'gives the install command when the Graph SDK is the gap' {
        $c = @($script:Checks | Where-Object { $_.Check -eq 'Microsoft.Graph.Authentication' })[0]
        if ($c.Status -eq 'Ready') {
            $c.Detail | Should -Match 'is installed'
        }
        else {
            $c.Action | Should -Match 'Install-Module Microsoft\.Graph\.Authentication'
            $c.Blocking | Should -BeTrue
        }
    }

    It 'calls an empty inventory what it is: a run that cannot detect anything' {
        $missing = Join-Path ([System.IO.Path]::GetTempPath()) ("none-{0}.json" -f [Guid]::NewGuid())
        $checks = @(& $script:Module { param($p) Test-TripwireReadiness -Path $p } $missing)
        $c = @($checks | Where-Object { $_.Check -eq 'Decoy inventory' })[0]
        $c.Status | Should -Be 'Action required'
        $c.Detail | Should -Match 'blind, not quiet'
        $c.Action | Should -Match 'New-TripwireDecoy'
    }

    It 'reports a corrupt inventory as a named gap with a fix, not as a raw exception' {
        # Get-TripwireDecoy throws on unreadable JSON by design. Readiness is the one place
        # that must catch it: a first run should be told which file is broken, not handed
        # the stack of the command that tripped over it.
        $bad = Join-Path ([System.IO.Path]::GetTempPath()) ("bad-{0}.json" -f [Guid]::NewGuid())
        Set-Content -LiteralPath $bad -Value '{ this is not json'
        try {
            $checks = $null
            { $script:Corrupt = @(& $script:Module { param($p) Test-TripwireReadiness -Path $p } $bad) } | Should -Not -Throw
            $checks = $script:Corrupt
            $c = @($checks | Where-Object { $_.Check -eq 'Decoy inventory' })[0]
            $c.Status | Should -Be 'Action required'
            $c.Blocking | Should -BeTrue
            $c.Detail | Should -Match 'not valid JSON'
        }
        finally {
            Remove-Item -LiteralPath $bad -ErrorAction SilentlyContinue
        }
    }

    It 'treats a missing EntraTripwirePro as a fact, never as a fault' {
        Remove-ProStub -Module $script:Module
        $checks = @(& $script:Module { Test-TripwireReadiness })
        $c = @($checks | Where-Object { $_.Check -eq 'EntraTripwirePro' })[0]
        $c.Status | Should -Be 'Not installed'
        $c.Blocking | Should -BeFalse
        $c.Detail | Should -Match 'needs nothing else'
    }
}

Describe 'The summary says what to do, and never overstates what was found' {

    It 'calls an empty result a possible blind run rather than a clean tenant' {
        $s = & $script:Module { @() | Get-TripwireSummary }
        $s.Total | Should -Be 0
        $s.Verdict | Should -Match 'blind run'
        @($s.NextSteps | ForEach-Object { $_.Command }) | Should -Contain 'Get-TripwireDecoy'
    }

    It 'leads with containment only when something reached the band containment acts on' {
        $trips = @(Watch-TripwireActivity -Demo)
        $s = & $script:Module { param($t) $t | Get-TripwireSummary -Demo } $trips
        $s.High | Should -Be 1
        $s.ContainmentEligible | Should -Be 1
        ($s.NextSteps[1].Command) | Should -Match 'Invoke-TripwireContainment'
        $s.Verdict | Should -Match 'High band'
    }

    It 'does not send you to build a baseline for trips a baseline cannot help' {
        # Every degraded trip in the fixtures is audit-sourced, and a directory audit record
        # carries no origin at all. Suggesting Get-TripwireBaseline -Build there would be
        # advice that cannot work, which is worse than none.
        $trips = @(Watch-TripwireActivity -Demo)
        $s = & $script:Module { param($t) $t | Get-TripwireSummary -Demo } $trips
        $s.Degraded | Should -BeGreaterThan 0
        @($s.NextSteps | ForEach-Object { $_.Command }) | Should -Not -Contain 'Get-TripwireBaseline -Build -Days 30 -Save'
        ($s.NextSteps | ForEach-Object { $_.Action }) -join ' ' | Should -Match 'carries no origin at all'
    }

    It 'prints commands shaped for the run that produced them' {
        $trips = @(Watch-TripwireActivity -Demo)
        $demo = & $script:Module { param($t) $t | Get-TripwireSummary -Demo } $trips
        $real = & $script:Module { param($t) $t | Get-TripwireSummary } $trips
        ($demo.NextSteps | ForEach-Object { $_.Command }) -join ' ' | Should -Match 'Watch-TripwireActivity -Demo'
        ($real.NextSteps | ForEach-Object { $_.Command }) -join ' ' | Should -Not -Match 'Watch-TripwireActivity -Demo'
    }

    It 'counts a degraded High trip as found but not as containment-eligible' {
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512') `
            -Decoy (New-TestDecoy) -Baseline $null -DistinctDecoyCount 4
        $trip.Degraded | Should -BeTrue
        $s = & $script:Module { param($t) $t | Get-TripwireSummary } $trip
        $s.ContainmentEligible | Should -Be 0
    }
}

Describe 'Nothing in this module writes to the host' {

    It 'uses no Write-Host anywhere in the module source' {
        # The narration is on the information stream on purpose. Write-Host writes to a
        # channel that cannot be captured, redirected or silenced, so a run in a scheduled
        # task would print into the void and a test could not assert on a single word of it.
        # Parsed rather than grepped. A comment that NAMES Write-Host while explaining why
        # the module does not use it is not a use of it, and a test that cannot tell the
        # difference would push the explanation out of the source to stay green.
        $offenders = @(foreach ($f in $script:Files) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref] $null, [ref] $null)
                $calls = $ast.FindAll({
                        param($n)
                        $n -is [System.Management.Automation.Language.CommandAst] -and
                        $n.GetCommandName() -eq 'Write-Host'
                    }, $true)
                if (@($calls).Count -gt 0) { $f.Name }
            })
        $offenders | Should -BeNullOrEmpty
    }
}

Describe 'Colour is decoration, and every way of turning it off works' {

    It 'emits no escape sequence at all when NO_COLOR is set' {
        # Set for the whole file in BeforeAll. Every line this module writes says what it
        # means in words, so stripping the colour must lose nothing -- and a terminal that
        # asked for no colour must get none, not fewer.
        $p = & $script:Module { Get-TripwirePalette }
        (@($p.Values) -join '') | Should -BeNullOrEmpty
    }

    It 'does emit them when the host wants colour, so the check above is not vacuous' {
        $previousNoColor = $env:NO_COLOR
        $previousRendering = $PSStyle.OutputRendering
        try {
            $env:NO_COLOR = ''
            $PSStyle.OutputRendering = 'Ansi'
            $p = & $script:Module { Get-TripwirePalette }
            (@($p.Values) -join '') | Should -Not -BeNullOrEmpty
        }
        finally {
            $PSStyle.OutputRendering = $previousRendering
            $env:NO_COLOR = $previousNoColor
        }
    }

    It 'degrades to plain text when the host renders plain text' {
        $previousNoColor = $env:NO_COLOR
        $previousRendering = $PSStyle.OutputRendering
        try {
            $env:NO_COLOR = ''
            $PSStyle.OutputRendering = 'PlainText'
            $p = & $script:Module { Get-TripwirePalette }
            (@($p.Values) -join '') | Should -BeNullOrEmpty
        }
        finally {
            $PSStyle.OutputRendering = $previousRendering
            $env:NO_COLOR = $previousNoColor
        }
    }
}

Describe 'The published surface' {

    It 'still exports the fourteen documented commands, unrenamed' {
        # The guard against breaking somebody's script. Commands may be ADDED to the
        # manifest; none of these may change name or disappear.
        $exported = @((Get-Module EntraTripwire).ExportedFunctions.Keys | Sort-Object)
        foreach ($name in @(
                'Connect-EntraTripwire', 'Disconnect-EntraTripwire', 'Enable-TripwirePro',
                'Export-TripwireReport', 'Get-TripwireBaseline', 'Get-TripwireDecoy',
                'Get-TripwireLicense', 'Get-TripwirePolicy', 'Invoke-TripwireAnalysis',
                'Invoke-TripwireContainment', 'Measure-TripwireConfidence', 'New-TripwireDecoy',
                'Remove-TripwireDecoy', 'Watch-TripwireActivity')) {
            $exported | Should -Contain $name
        }
    }

    It 'defines the three guided-experience commands inside the module' {
        foreach ($name in @('Start-EntraTripwire', 'Test-TripwireReadiness', 'Get-TripwireSummary')) {
            $found = & $script:Module { param($n) Get-Command -Name $n -ErrorAction SilentlyContinue } $name
            $found | Should -Not -BeNullOrEmpty -Because "$name must exist for the guided run to work"
        }
    }
}
