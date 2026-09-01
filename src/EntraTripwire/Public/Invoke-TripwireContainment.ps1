<#
.SYNOPSIS
    Plan -- and, with a Pro licence and an explicit -Execute, perform -- containment of a
    high-confidence trip.

.DESCRIPTION
    Containment is the part of this tool that can hurt, so it is fenced on five sides. All
    five must be open before a single Graph write is issued:

      1. The trip must be in the High band. Medium is an alert for a human, never an action.
      2. The trip must not be Degraded. A score computed with a withheld signal is a FLOOR,
         and acting on a floor means acting on a number you know is incomplete. -AcceptDegraded
         overrides this, and says so in the plan and the log.
      3. -Execute must be passed. The default is a dry run that returns the plan and touches
         nothing. There is no configuration setting that changes this default.
      4. ShouldProcess must confirm, so -WhatIf and -Confirm behave as an operator expects.
      5. The 'containment' Pro feature must be licensed. Without it the plan is returned in
         full -- including every parameter needed to run the actions by hand -- and nothing
         is executed.

    What it does, at most:
      * Revoke the actor's refresh tokens (POST users/{id}/revokeSignInSessions), only when
        the actor is a directory principal in this tenant.
      * Disable the decoy that was touched, so a credential that is now known to be in an
        intruder's hands stops working.
      * Write an incident capture to disk: the trip, its signals, the actor context.

    What it will NEVER do, by construction rather than by policy: contact, probe, scan or
    respond to the source address; feed the intruder anything; disable a non-decoy identity
    other than the actor; grant a permission; enable anything. The write allowlist in
    Invoke-TripwireGraphWrite has no entry for any of it, and its only PATCH bodies are
    {"accountEnabled": false} -- the gateway can disable and is structurally incapable of
    enabling.

.PARAMETER Trip
    A scored trip from Watch-TripwireActivity or Invoke-TripwireAnalysis.

.PARAMETER Action
    Which actions to include. Defaults to all three.

.PARAMETER Execute
    Actually perform the plan. Requires the containment Pro feature.

.PARAMETER AcceptDegraded
    Allow containment on a trip that was scored with a signal withheld.

.PARAMETER CapturePath
    Directory for incident captures. Defaults to ./incidents.

.EXAMPLE
    Watch-TripwireActivity -Demo | Where-Object Band -eq 'High' | Invoke-TripwireContainment

.EXAMPLE
    $trip | Invoke-TripwireContainment -Execute -Confirm
#>
function Invoke-TripwireContainment {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Trip,
        [ValidateSet('RevokeActorSessions', 'DisableDecoy', 'CaptureContext')]
        [string[]] $Action = @('RevokeActorSessions', 'DisableDecoy', 'CaptureContext'),
        [switch] $Execute,
        [switch] $AcceptDegraded,
        [string] $CapturePath = './incidents'
    )

    process {
        $blockers = [System.Collections.Generic.List[string]]::new()

        if ($Trip.Band -ne 'High') {
            $blockers.Add("Confidence $($Trip.Confidence) is in the $($Trip.Band) band. Containment is eligible in the High band only.")
        }
        if ($Trip.Degraded -and -not $AcceptDegraded) {
            $blockers.Add("Scored with signals withheld ($(@($Trip.Withheld) -join ', ')). The confidence is a lower bound, not a measurement. Pass -AcceptDegraded to proceed anyway.")
        }

        $plan = [System.Collections.Generic.List[object]]::new()
        $actorId = [string]$Trip.Touch.actor.id

        if ($Action -contains 'RevokeActorSessions') {
            if ([string]::IsNullOrWhiteSpace($actorId)) {
                $plan.Add([pscustomobject]@{ Name = 'RevokeActorSessions'; Method = $null; Path = $null; Eligible = $false; Why = 'The actor has no directory object id (an anonymous or external principal). There are no sessions in this tenant to revoke.' })
            }
            else {
                $plan.Add([pscustomobject]@{ Name = 'RevokeActorSessions'; Method = 'POST'; Path = "/v1.0/users/$actorId/revokeSignInSessions"; Eligible = $true; Why = "Invalidate every refresh token held by $($Trip.ActorLabel)." })
            }
        }

        if ($Action -contains 'DisableDecoy') {
            $decoyObjectId = [string]$Trip.Touch.actor.id
            if ($Trip.Touch.source -ne 'SignInLog') { $decoyObjectId = '' }
            if ([string]::IsNullOrWhiteSpace($decoyObjectId)) {
                $plan.Add([pscustomobject]@{ Name = 'DisableDecoy'; Method = $null; Path = $null; Eligible = $false; Why = 'The touch came from the directory audit log, so the decoy was read rather than used. Disabling it would only tell the intruder they were seen.' })
            }
            else {
                $plan.Add([pscustomobject]@{ Name = 'DisableDecoy'; Method = 'PATCH'; Path = "/v1.0/users/$decoyObjectId"; Body = @{ accountEnabled = $false }; Eligible = $true; Why = "Decoy '$($Trip.DecoyName)' was authenticated with, so its credential is in an intruder's hands." })
            }
        }

        if ($Action -contains 'CaptureContext') {
            $plan.Add([pscustomobject]@{ Name = 'CaptureContext'; Method = $null; Path = (Join-Path $CapturePath "$($Trip.TouchId).json"); Eligible = $true; Why = 'Preserve the trip, its signals and the actor context for attribution. Written locally; nothing is sent anywhere.' })
        }

        $licensed = Test-TripwireFeature -Feature 'containment'
        if ($Execute -and -not $licensed) {
            $blockers.Add('Automated containment is an EntraTripwire Pro feature. The plan below is complete: every action lists the exact Graph call, so it can be run by hand. See docs/PRO.md.')
        }

        $willExecute = $Execute -and $licensed -and $blockers.Count -eq 0
        $performed = [System.Collections.Generic.List[object]]::new()

        if ($willExecute) {
            foreach ($step in $plan) {
                if (-not $step.Eligible) { continue }
                $target = "$($Trip.DecoyName) / $($Trip.ActorLabel)"
                if (-not $PSCmdlet.ShouldProcess($target, $step.Name)) {
                    $performed.Add([pscustomobject]@{ Name = $step.Name; Status = 'Declined'; Detail = 'Not confirmed.' })
                    continue
                }
                try {
                    switch ($step.Name) {
                        'CaptureContext' {
                            if (-not (Test-Path -LiteralPath $CapturePath)) { New-Item -ItemType Directory -Path $CapturePath -Force | Out-Null }
                            $Trip | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $step.Path -Encoding utf8
                            $performed.Add([pscustomobject]@{ Name = $step.Name; Status = 'Done'; Detail = $step.Path })
                        }
                        'DisableDecoy' {
                            Invoke-TripwireGraphWrite -Method 'PATCH' -Path $step.Path -Body $step.Body | Out-Null
                            $performed.Add([pscustomobject]@{ Name = $step.Name; Status = 'Done'; Detail = $step.Path })
                        }
                        default {
                            Invoke-TripwireGraphWrite -Method 'POST' -Path $step.Path | Out-Null
                            $performed.Add([pscustomobject]@{ Name = $step.Name; Status = 'Done'; Detail = $step.Path })
                        }
                    }
                }
                catch {
                    # A failed containment action is reported as failed. It is never folded
                    # into a summary that says the incident was contained.
                    Write-TripwireLog -Level 'Warn' -Message "Containment step $($step.Name) FAILED: $($_.Exception.Message)"
                    $performed.Add([pscustomobject]@{ Name = $step.Name; Status = 'Failed'; Detail = $_.Exception.Message })
                }
            }
        }

        [pscustomobject]@{
            TouchId     = $Trip.TouchId
            DecoyName   = $Trip.DecoyName
            ActorLabel  = $Trip.ActorLabel
            Confidence  = $Trip.Confidence
            Band        = $Trip.Band
            Mode        = if ($willExecute) { 'Executed' } else { 'DryRun' }
            Licensed    = $licensed
            Blockers    = @($blockers)
            Plan        = @($plan)
            Performed   = @($performed)
        }
    }
}
