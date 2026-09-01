#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The report.

    Two properties matter and both are security properties. Every string in a trip is
    attacker-influenced -- display names, operations, source addresses come from the
    directory and from log records an intruder can shape -- so the renderer must escape
    all of it. And the coverage line must appear ABOVE the findings, because a quiet report
    from a blind run is the failure mode that looks like good news.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'EntraTripwire'
    Import-Module (Join-Path $script:SourceRoot 'EntraTripwire.psd1') -Force
    $script:Module = Get-Module EntraTripwire
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
}

Describe 'Escaping attacker-controlled strings' {

    It 'escapes a script tag smuggled through a decoy display name' {
        $decoy = New-TestDecoy -DisplayName '<script>alert(1)</script>'
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy $decoy -Baseline (New-TestBaseline)
        $html = & $script:Module { param($t) ConvertTo-TripwireHtmlReport -Trip @($t) } $trip

        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;alert'
    }

    It 'escapes an attribute break smuggled through the operation field' {
        $touch = New-TestTouch -Operation 'Sign-in" onload="alert(1)'
        $trip = Measure-TripwireConfidence -Touch $touch -Decoy (New-TestDecoy) -Baseline (New-TestBaseline)
        $html = & $script:Module { param($t) ConvertTo-TripwireHtmlReport -Trip @($t) } $trip
        $html | Should -Not -Match 'onload="alert'
    }

    It 'produces a self-contained document with no external resource' {
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline (New-TestBaseline)
        $html = & $script:Module { param($t) ConvertTo-TripwireHtmlReport -Trip @($t) } $trip
        $html | Should -Not -Match 'src="http|href="http|@import|cdn\.'
        $html | Should -Match '<!doctype html>'
    }
}

Describe 'Coverage is reported with the findings, not below them' {

    It 'warns at the top of the report when any trip was scored degraded' {
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline $null
        $html = & $script:Module { param($t) ConvertTo-TripwireHtmlReport -Trip @($t) } $trip
        $html | Should -Match 'scored with at least one signal withheld'
        # The banner must precede the table.
        $html.IndexOf('signal withheld') | Should -BeLessThan $html.IndexOf('<table>')
    }

    It 'names the withheld signals on the trip itself' {
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline $null
        $html = & $script:Module { param($t) ConvertTo-TripwireHtmlReport -Trip @($t) } $trip
        $html | Should -Match 'withheld: OriginAnomaly'
    }

    It 'says so when a run used the demo fixtures, so a demo report cannot be mistaken for a real one' {
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline (New-TestBaseline)
        $html = & $script:Module { param($t) ConvertTo-TripwireHtmlReport -Trip @($t) -Demo } $trip
        $html | Should -Match 'DEMO MODE'
        $html | Should -Match 'No tenant was contacted'
    }

    It 'shows a suppressed trip with its reason instead of hiding it' {
        $b = New-TestBaseline -SuppressedActors @('actor-1')
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline $b
        $html = & $script:Module { param($t) ConvertTo-TripwireHtmlReport -Trip @($t) } $trip
        $html | Should -Match 'Suppressed: Actor actor-1 is on the tenant suppression allowlist'
    }

    It 'counts each band' {
        $trips = @(
            Measure-TripwireConfidence -Touch (New-TestTouch -Timestamp '2026-06-15T03:00:00Z' -Country 'KP' -Asn '64512') -Decoy (New-TestDecoy) -Baseline (New-TestBaseline) -DistinctDecoyCount 4
            Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline (New-TestBaseline)
        )
        $html = & $script:Module { param($t) ConvertTo-TripwireHtmlReport -Trip $t } $trips
        $html | Should -Match '<div class="n">1</div><div class="l">High confidence</div>'
        $html | Should -Match '<div class="n">1</div><div class="l">Low</div>'
    }
}

Describe 'Export' {

    It 'writes the file and returns its path' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("r-{0}.html" -f [Guid]::NewGuid())
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline (New-TestBaseline)
        $returned = $trip | Export-TripwireReport -Path $out -Confirm:$false
        $returned | Should -Be $out
        (Get-Content -LiteralPath $out -Raw) | Should -Match 'EntraTripwire'
        Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
    }

    It 'writes nothing under -WhatIf' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("r-{0}.html" -f [Guid]::NewGuid())
        $trip = Measure-TripwireConfidence -Touch (New-TestTouch) -Decoy (New-TestDecoy) -Baseline (New-TestBaseline)
        $trip | Export-TripwireReport -Path $out -WhatIf | Out-Null
        Test-Path -LiteralPath $out | Should -BeFalse
    }
}
