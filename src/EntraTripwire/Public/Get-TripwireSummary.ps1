<#
.SYNOPSIS
    Reduce a set of scored trips to one verdict and the next thing to do.

.DESCRIPTION
    A list of trips is evidence. It is not an answer. This command answers the two
    questions an administrator actually has after a run -- is anything wrong, and what do
    I type next -- from the trips themselves, so the answer cannot drift from the data.

    Three rules it keeps:

      * It never upgrades the verdict. The bands come from the scoring policy and nothing
        here re-reads them.
      * It never calls a quiet result a clean one. Zero trips with an empty inventory is a
        blind run, and the next steps say so instead of congratulating anybody.
      * It reports withheld signals as withheld. A degraded trip's confidence is a floor,
        and the next steps name the usual cause -- no baseline -- separately from the
        unavoidable one: a directory audit record carries no origin at all.

.PARAMETER Trip
    Scored trips from Watch-TripwireActivity or Invoke-TripwireAnalysis. An empty set is
    valid and produces the blind-run verdict.

.PARAMETER Demo
    Shape the suggested commands for a demo run, so they can be pasted as printed.

.EXAMPLE
    Watch-TripwireActivity -Demo | Get-TripwireSummary -Demo

.EXAMPLE
    (Watch-TripwireActivity -Demo | Get-TripwireSummary).NextSteps
#>
function Get-TripwireSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(ValueFromPipeline)] [AllowNull()] $Trip,
        [switch] $Demo
    )

    begin { $collected = [System.Collections.Generic.List[object]]::new() }
    process { if ($null -ne $Trip) { $collected.Add($Trip) } }

    end {
        $trips = @($collected)
        $high = @($trips | Where-Object { $_.Band -eq 'High' })
        $medium = @($trips | Where-Object { $_.Band -eq 'Medium' })
        $low = @($trips | Where-Object { $_.Band -eq 'Low' })
        $suppressed = @($trips | Where-Object { $_.Band -eq 'Suppressed' })
        $degraded = @($trips | Where-Object { $_.Degraded })
        $eligible = @($high | Where-Object { -not $_.Degraded })

        # Degraded splits in two, and conflating them would send the operator to build a
        # baseline that cannot fix the second kind. A sign-in record carries an origin; a
        # directory audit record does not, so an audit-sourced touch is degraded however
        # good the baseline is.
        $degradedAudit = @($degraded | Where-Object { $_.Touch.source -ne 'SignInLog' }).Count
        $degradedSignIn = $degraded.Count - $degradedAudit

        $suffix = if ($Demo) { ' -Demo' } else { '' }
        $watch = "Watch-TripwireActivity$suffix"

        $top = 0.0
        if ($trips.Count -gt 0) {
            $top = @($trips | Sort-Object -Property Confidence -Descending)[0].Confidence
        }

        $verdict =
        if ($trips.Count -eq 0) {
            'No touch on a decoy was recorded. That is good news only if decoys are planted and the window covered them -- otherwise it is a blind run reading like a quiet tenant.'
        }
        elseif ($high.Count -gt 0) {
            "$($high.Count) trip(s) reached the High band, the only band containment is eligible in. Review them before anything else."
        }
        elseif ($medium.Count -gt 0) {
            "Nothing reached the High band. $($medium.Count) trip(s) are Medium: evidence worth a human look, never an automatic action."
        }
        elseif ($low.Count -gt 0) {
            "$($low.Count) trip(s) scored Low. Decoys were touched, but not in a pattern this engine calls an intrusion."
        }
        else {
            "Every one of the $($suppressed.Count) touch(es) in this run was suppressed by a known-benign rule. Each is listed with its reason rather than hidden."
        }

        $steps = [System.Collections.Generic.List[object]]::new()
        function Add-Step {
            param([Parameter(Mandatory)] [string] $Action, [string] $Command = '')
            $steps.Add([pscustomobject]@{
                    PSTypeName = 'EntraTripwire.NextStep'
                    Step       = $steps.Count + 1
                    Action     = $Action
                    Command    = $Command
                })
        }

        if ($trips.Count -eq 0) {
            Add-Step -Action 'Confirm decoys are planted. An empty inventory detects nothing and says nothing.' -Command 'Get-TripwireDecoy'
            Add-Step -Action 'Widen the window. Entra keeps directory audits for about 30 days.' -Command "$watch -Days 7"
            if (-not $Demo) {
                Add-Step -Action 'See the whole path end to end against the shipped fixtures, with no tenant.' -Command 'Start-EntraTripwire -Demo'
            }
        }
        else {
            if ($high.Count -gt 0) {
                Add-Step -Action 'Read the signals behind the highest-scoring trip. Every one carries its raw strength, its weight and a rationale.' `
                    -Command "($watch | Sort-Object Confidence -Descending)[0].Signals | Format-Table Name, Raw, Weight, Available, Rationale"
                Add-Step -Action 'Plan containment. The default is a dry run: it returns the exact Graph call for every action and touches nothing.' `
                    -Command "$watch | Where-Object Band -eq 'High' | Invoke-TripwireContainment"
            }
            if ($medium.Count -gt 0 -and $high.Count -eq 0) {
                Add-Step -Action 'Look at the Medium trips by hand. Containment will not act on them, by design.' `
                    -Command "$watch | Where-Object Band -eq 'Medium' | Format-List DecoyName, ActorLabel, Confidence, Withheld"
            }
            if ($degradedSignIn -gt 0 -and -not $Demo) {
                Add-Step -Action "$degradedSignIn sign-in trip(s) were scored with a signal withheld, so their confidence is a floor. A baseline is what the origin and off-hours signals compare against." `
                    -Command 'Get-TripwireBaseline -Build -Days 30 -Save'
            }
            if ($degradedAudit -gt 0) {
                Add-Step -Action "$degradedAudit trip(s) came from the directory audit log, which carries no origin at all. They stay degraded whatever the baseline says; weigh them on purity and fan-out."
            }
            if ($suppressed.Count -gt 0) {
                Add-Step -Action "$($suppressed.Count) touch(es) were suppressed. If one of them should have alerted, the allowlist is the first place to look." `
                    -Command "(Get-TripwireBaseline$suffix).suppressedActors"
            }
            Add-Step -Action 'Keep the evidence. The HTML report is one self-contained file that opens with no network.' `
                -Command "$watch | Export-TripwireReport -Path ./tripwire-report.html$suffix"
        }

        [pscustomobject]@{
            PSTypeName          = 'EntraTripwire.Summary'
            Total               = $trips.Count
            High                = $high.Count
            Medium              = $medium.Count
            Low                 = $low.Count
            Suppressed          = $suppressed.Count
            Degraded            = $degraded.Count
            ContainmentEligible = $eligible.Count
            TopConfidence       = $top
            Verdict             = $verdict
            NextSteps           = $steps.ToArray()
        }
    }
}

# Eight properties, so PowerShell renders this as a list rather than a table -- which is
# what a verdict wants. NextSteps is left off the default set because it is a collection:
# it prints on its own, or through Start-EntraTripwire, which lays it out.
Update-TypeData -TypeName 'EntraTripwire.Summary' `
    -DefaultDisplayPropertySet 'Total', 'High', 'Medium', 'Low', 'Suppressed', 'Degraded', 'ContainmentEligible', 'Verdict' -Force

Update-TypeData -TypeName 'EntraTripwire.NextStep' -DefaultDisplayPropertySet 'Step', 'Action', 'Command' -Force
