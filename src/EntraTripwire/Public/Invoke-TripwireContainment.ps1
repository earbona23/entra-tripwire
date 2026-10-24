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
        intruder's hands stops working. The object id disabled is the one recorded in the
        LOCAL decoy inventory, and the action is refused outright when the sign-in record
        names a different principal than the inventory does. A log record is shaped by the
        actor it describes; the inventory is the only thing in this system that knows what
        is bait, so it is the only thing allowed to nominate an object for disabling.
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
            # The object id comes from the LOCAL INVENTORY, never from the log record. A
            # log record is shaped by the actor it describes, and the decoy index matches
            # on four different identifiers, so "the principal named in this record" and
            # "the decoy I planted" are not guaranteed to be the same object. Only the
            # inventory knows what is bait, and this gateway will only disable bait.
            $decoyObjectId = [string]$Trip.DecoyObjectId
            $refusal = $null
            if ($Trip.Touch.source -ne 'SignInLog') {
                $refusal = 'The touch came from the directory audit log, so the decoy was read rather than used. Disabling it would only tell the intruder they were seen.'
            }
            elseif ([string]::IsNullOrWhiteSpace($decoyObjectId)) {
                $refusal = "Decoy '$($Trip.DecoyName)' has no object id in the local inventory, so there is no object this tool can prove is bait. Re-register it with New-TripwireDecoy -RegisterOnly -ObjectId."
            }
            elseif ($Trip.DecoyType -ne 'User') {
                $refusal = "Decoy '$($Trip.DecoyName)' is of type '$($Trip.DecoyType)'. Only a decoy user is disabled automatically; disabling an application means disabling its service principal, whose object id this tool does not hold. Revoke the credential in the portal."
            }
            elseif ($decoyObjectId -ne $actorId) {
                $refusal = "The sign-in record names principal '$actorId', but the inventory records decoy '$($Trip.DecoyName)' as object '$decoyObjectId'. They disagree, so EntraTripwire will not disable either. Reconcile the inventory before containing by hand."
            }

            if ($refusal) {
                $plan.Add([pscustomobject]@{ Name = 'DisableDecoy'; Method = $null; Path = $null; Eligible = $false; Why = $refusal })
            }
            else {
                $plan.Add([pscustomobject]@{ Name = 'DisableDecoy'; Method = 'PATCH'; Path = "/v1.0/users/$decoyObjectId"; Body = @{ accountEnabled = $false }; Eligible = $true; Why = "Decoy '$($Trip.DecoyName)' was authenticated with, so its credential is in an intruder's hands." })
            }
        }

        if ($Action -contains 'CaptureContext') {
            $plan.Add([pscustomobject]@{ Name = 'CaptureContext'; Method = $null; Path = (Join-Path $CapturePath "$($Trip.TouchId).json"); Eligible = $true; Why = 'Preserve the trip, its signals and the actor context for attribution. Written locally; nothing is sent anywhere.' })
        }

        # Executing the plan is the paid capability, and it is the only part that is. The
        # plan above was built here, in full, with the exact Graph call for every action,
        # so it can be run by hand at no cost -- which is why the refusal below says what
        # the operator still has rather than only what they lack.
        $canExecute = Test-TripwireProFeature -Feature 'containment'
        if ($Execute -and -not $canExecute) {
            $blockers.Add("Executing a containment plan needs EntraTripwirePro, which is not installed. $((Get-TripwireProvider).Reason) The plan below is complete: every action lists the exact Graph call, so it can be run by hand.")
        }

        $willExecute = $Execute -and $canExecute -and $blockers.Count -eq 0
        $performed = [System.Collections.Generic.List[object]]::new()

        if ($willExecute) {
            # Confirmation is answered here, by the command the operator actually invoked,
            # and only confirmed steps are handed over. The paid module never decides
            # whether an action was authorised; it issues the ones that were.
            $confirmed = [System.Collections.Generic.List[object]]::new()
            foreach ($step in $plan) {
                if (-not $step.Eligible) { continue }
                $target = "$($Trip.DecoyName) / $($Trip.ActorLabel)"
                if (-not $PSCmdlet.ShouldProcess($target, $step.Name)) {
                    $performed.Add([pscustomobject]@{ Name = $step.Name; Status = 'Declined'; Detail = 'Not confirmed.' })
                    continue
                }
                $confirmed.Add($step)
            }

            if ($confirmed.Count -gt 0) {
                # The write gateway goes with the call. It carries this module's session
                # state, so every write the paid module issues is still checked against the
                # allowlist in this repository and cannot reach Graph any other way.
                $results = @(Invoke-TripwireProCapability -Capability 'Containment' -Arguments @{
                        Step        = $confirmed.ToArray()
                        Trip        = $Trip
                        CapturePath = $CapturePath
                        Writer      = ${function:Invoke-TripwireGraphWrite}
                    })
                foreach ($r in $results) {
                    # A failed containment action is reported as failed. It is never folded
                    # into a summary that says the incident was contained.
                    if ($r.Status -eq 'Failed') {
                        Write-TripwireLog -Level 'Warn' -Message "Containment step $($r.Name) FAILED: $($r.Detail)"
                    }
                    $performed.Add($r)
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
            # Kept under its old name so a script that read it does not break. It now
            # means the paid module is installed and provides containment.
            Licensed    = $canExecute
            Blockers    = @($blockers)
            Plan        = @($plan)
            Performed   = @($performed)
        }
    }
}
