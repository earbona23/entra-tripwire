<#
.SYNOPSIS
    The guided run: readiness, a target, decoys, a watch, a verdict and an HTML report.

.DESCRIPTION
    One command that takes an administrator who has never seen this tool from nothing to a
    report they can read. It narrates every step, asks only what it cannot work out, and
    confirms before anything is written to a tenant.

        Start-EntraTripwire -Demo

    is the whole evaluation: it scores the synthetic fixtures that ship inside the module,
    with no tenant, no credentials, no network and no Microsoft Graph SDK installed, and
    writes the same HTML report a real run produces.

    The order of the steps is the point. Readiness is checked BEFORE a target is chosen,
    so a missing SDK is a sentence rather than an exception. Intent is settled BEFORE the
    connection, so consent is asked for the scopes the run actually needs -- an operator
    who only wants detection is never asked to approve writes. Only then does anything
    happen.

    Two guarantees worth stating plainly:

      * Nothing is written to a tenant without an interactive confirmation. The guided run
        has exactly one write -- planting a decoy user -- and -NonInteractive never reaches
        it, because the offer is only made to a session that can be asked. Containment is
        not part of this command at all: it prints the command and stops.
      * Nothing here decides a verdict. Every number comes from Watch-TripwireActivity and
        the scoring policy; this command arranges them and says what to do next.

.PARAMETER Demo
    Run against the fixtures shipped inside the module. No tenant is contacted.

.PARAMETER TenantId
    The tenant to run against. Without it, and without -Demo, an interactive session is
    asked for one and offered the demo instead.

.PARAMETER Days
    How far back to read. Entra keeps directory audit logs for about 30 days.

.PARAMETER ReportPath
    Where to write the HTML report. Defaults to a timestamped file in the working directory.

.PARAMETER NoReport
    Skip the report. The trips are still returned on the object.

.PARAMETER NoOpen
    Write the report but do not open it. Implied by -NonInteractive.

.PARAMETER NonInteractive
    Ask nothing. Suitable for a scheduled run, and unable to write to a tenant.

.EXAMPLE
    Start-EntraTripwire -Demo

    Thirty seconds, no tenant: the whole path end to end against the shipped fixtures.

.EXAMPLE
    Start-EntraTripwire -TenantId contoso.onmicrosoft.com

    Guided run against a tenant. Detection-only unless you accept the offer to plant.

.EXAMPLE
    $run = Start-EntraTripwire -TenantId contoso.onmicrosoft.com -NonInteractive -Days 1
    $run.Summary.Verdict

    A scheduled run. It reads, scores and reports; it cannot write.
#>
function Start-EntraTripwire {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [switch] $Demo,
        [string] $TenantId,
        [ValidateRange(1, 365)] [int] $Days = 1,
        [string] $ReportPath,
        [switch] $NoReport,
        [switch] $NoOpen,
        [switch] $NonInteractive
    )

    # The narration is the product here, so it is on by default -- but on the INFORMATION
    # stream, not the host, so -InformationAction SilentlyContinue silences it and
    # -InformationVariable captures it. Only set when the caller did not say otherwise.
    if (-not $PSBoundParameters.ContainsKey('InformationAction')) {
        $InformationPreference = 'Continue'
    }

    $interactive = -not $NonInteractive
    $step = 0
    $totalSteps = 5

    # Argument validation, so it happens before anything is printed or probed. A session
    # that cannot be asked a question must be given the answer on the command line, and
    # this command will not pick a tenant -- or silently fall back to the demo -- for it.
    if (-not $Demo -and -not $TenantId -and -not $interactive) {
        throw 'Start-EntraTripwire needs a target: pass -TenantId <tenant> for a real run, or -Demo to score the shipped fixtures. It will not pick one for you in a non-interactive session.'
    }

    $banner = 'EntraTripwire'
    try {
        $self = $ExecutionContext.SessionState.Module
        # Guarded on Major: the loader can be imported directly as a .psm1, which has no
        # manifest and therefore reports version 0.0. A version of "0.0" in a banner reads
        # as a broken install, so it is simply left out.
        if ($null -ne $self -and $null -ne $self.Version -and $self.Version.Major -gt 0) {
            $banner = "EntraTripwire $($self.Version)"
        }
    }
    catch { $banner = 'EntraTripwire' }

    Write-TripwireNotice ''
    Write-TripwireNotice "$banner -- guided run" -Kind Heading
    Write-TripwireNotice 'Deception-based intrusion detection for Microsoft Entra ID.' -Kind Detail
    Write-TripwireNotice ''

    # ---------------------------------------------------------------- 1. readiness ----
    $step++
    Write-TripwireNotice "[$step/$totalSteps] Readiness" -Kind Heading
    $readiness = @(Test-TripwireReadiness)

    foreach ($c in $readiness) {
        # In demo mode the tenant-side checks are not gaps, they are "not needed", and
        # reporting them as problems is how a tool teaches people to ignore its output.
        if ($Demo -and $c.NeededFor -ne 'Any run') {
            if ($c.Status -ne 'Ready') { continue }
        }
        # 'Not installed' is reserved for EntraTripwirePro, which is a normal state and
        # not a finding. Marking it as one is how a tool trains people to skim its output.
        $kind = if ($c.Status -eq 'Ready') { 'Ok' }
        elseif ($c.Status -eq 'Not installed') { 'Neutral' }
        elseif ($c.Blocking) { 'Alert' }
        else { 'Attention' }
        Write-TripwireNotice "$($c.Check) -- $($c.Detail)" -Kind $kind -Indent 1
        if ($c.Action) { Write-TripwireNotice "-> $($c.Action)" -Kind Command -Indent 4 }
    }

    if ($Demo) {
        Write-TripwireNotice 'Demo mode needs none of the tenant-side checks: no SDK, no connection, no inventory.' -Kind Detail -Indent 1
    }
    else {
        $blockers = @($readiness | Where-Object { $_.Status -eq 'Action required' -and $_.Blocking })
        if ($blockers.Count -gt 0) {
            Write-TripwireNotice ''
            Write-TripwireNotice "$($blockers.Count) thing(s) must be fixed before a tenant run. The commands are above." -Kind Alert -Indent 1
            Write-TripwireNotice 'Nothing to install for the demo: Start-EntraTripwire -Demo' -Kind Command -Indent 1
            # Returned rather than thrown. The operator asked for a guided run and this IS
            # the guidance; a stack trace would bury it.
            return [pscustomobject]@{
                PSTypeName = 'EntraTripwire.GuidedRun'
                Mode       = 'Blocked'
                TenantId   = $TenantId
                Days       = $Days
                Readiness  = $readiness
                Trips      = @()
                Summary    = $null
                ReportPath = $null
                Blockers   = $blockers
            }
        }
    }
    Write-TripwireNotice ''

    # ------------------------------------------------------------------- 2. target ----
    $step++
    Write-TripwireNotice "[$step/$totalSteps] Target" -Kind Heading

    if (-not $Demo -and -not $TenantId) {
        # Reachable only in an interactive session: the non-interactive case was answered
        # at the top of the function, before anything was printed.
        Write-TripwireNotice 'Tenant id or domain, e.g. contoso.onmicrosoft.com.' -Kind Detail -Indent 1
        Write-TripwireNotice 'Press Enter with nothing to run the demo instead.' -Kind Detail -Indent 1
        $answer = Read-Host '  Tenant'
        if ([string]::IsNullOrWhiteSpace($answer)) { $Demo = $true } else { $TenantId = $answer.Trim() }
    }

    $mode = if ($Demo) { 'Demo' } else { 'Tenant' }
    if ($Demo) {
        Write-TripwireNotice 'Demo: the synthetic fixtures inside the module. No tenant is contacted.' -Kind Ok -Indent 1
    }
    else {
        Write-TripwireNotice "Tenant $TenantId, reading the last $Days day(s) of sign-in and directory audit logs." -Kind Ok -Indent 1
    }
    Write-TripwireNotice ''

    # -------------------------------------------------------------------- 3. decoys ----
    $step++
    Write-TripwireNotice "[$step/$totalSteps] Decoys" -Kind Heading

    $planted = $null
    $decoys = @(Get-TripwireDecoy -Demo:$Demo)

    if ($Demo) {
        Write-TripwireNotice "$($decoys.Count) synthetic decoys, one of them deliberately contaminated so the suppression engine has something to suppress." -Kind Ok -Indent 1
    }
    elseif ($decoys.Count -gt 0) {
        Write-TripwireNotice "$($decoys.Count) decoy(s) already planted. Nothing to create." -Kind Ok -Indent 1
    }
    elseif (-not $interactive) {
        # A blind run announced as a blind run. The alternative -- planting without being
        # asked -- would have this command create directory objects unattended.
        Write-TripwireNotice 'The inventory is empty and this is a non-interactive run, which never writes to a tenant. The watch below is blind: it cannot detect a touch on a decoy that does not exist.' -Kind Attention -Indent 1
        Write-TripwireNotice "New-TripwireDecoy -Type User -DisplayName 'svc-backup-archive' -UserPrincipalName 'svc-backup-archive@your-domain'" -Kind Command -Indent 2
    }
    else {
        Write-TripwireNotice 'The inventory is empty, so there is nothing a run could detect yet.' -Kind Attention -Indent 1
        Write-TripwireNotice 'A decoy only works if it looks like it belongs. "svc-backup-archive" gets found; "DECOY_DO_NOT_USE" gets skipped. See docs/deception-design.md.' -Kind Detail -Indent 1
        Write-TripwireNotice 'Leave the name blank to skip planting and run detection-only.' -Kind Detail -Indent 1

        $name = Read-Host '  Decoy display name [Enter to skip]'
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $displayName = $name.Trim()
            $upn = Read-Host "  User principal name for '$displayName'"
            if ([string]::IsNullOrWhiteSpace($upn)) {
                Write-TripwireNotice 'No user principal name given, so nothing was planted. Continuing detection-only.' -Kind Attention -Indent 1
            }
            else {
                # The one place this command writes. ShouldProcess, so -WhatIf and -Confirm
                # behave, and it is reachable only from an interactive session.
                if ($PSCmdlet.ShouldProcess("$TenantId", "Create decoy user '$displayName' ($($upn.Trim()))")) {
                    try { Connect-EntraTripwire -TenantId $TenantId -Mode 'Plant' | Out-Null }
                    catch {
                        Write-TripwireNotice "Could not connect to $TenantId in Plant mode." -Kind Alert -Indent 1
                        Write-TripwireNotice $_.Exception.Message -Kind Detail -Indent 2
                        Write-TripwireNotice 'Nothing was created. Check the tenant id, and that the sign-in completed.' -Kind Detail -Indent 1
                        throw
                    }
                    $planted = New-TripwireDecoy -Type User -DisplayName $displayName -UserPrincipalName $upn.Trim() `
                        -Note 'Planted by the guided run.' -Confirm:$false
                    Write-TripwireNotice "Planted $($planted.id): $displayName. It holds no group, role, licence or permission, and its password was discarded." -Kind Ok -Indent 1
                    Write-TripwireNotice 'Seed its name where an intruder would look -- a stale wiki page, an old config file -- then come back.' -Kind Detail -Indent 1
                    $decoys = @(Get-TripwireDecoy)
                }
                else {
                    Write-TripwireNotice 'Declined. Nothing was created; continuing detection-only.' -Kind Attention -Indent 1
                }
            }
        }
        else {
            Write-TripwireNotice 'Skipped. Continuing detection-only.' -Kind Detail -Indent 1
        }
    }

    if (-not $Demo -and $null -eq $script:TripwireSession) {
        # Detect mode asks for two read scopes and nothing else, which is the whole reason
        # the consent decision comes after the planting decision rather than before it.
        Write-TripwireNotice 'Connecting in Detect mode: AuditLog.Read.All and Directory.Read.All, no write scopes.' -Kind Detail -Indent 1
        try { Connect-EntraTripwire -TenantId $TenantId -Mode 'Detect' | Out-Null }
        catch {
            # Rethrown, so a script still sees the real failure -- but narrated first,
            # because "Connect-MgGraph: ..." on its own does not say which of this
            # command's five steps was in progress or that nothing has changed yet.
            Write-TripwireNotice "Could not connect to $TenantId." -Kind Alert -Indent 1
            Write-TripwireNotice $_.Exception.Message -Kind Detail -Indent 2
            Write-TripwireNotice 'Check the tenant id, and that the sign-in completed in the browser. Nothing was read or changed.' -Kind Detail -Indent 1
            throw
        }
    }
    Write-TripwireNotice ''

    # ------------------------------------------------------------------ 4. the watch ----
    $step++
    Write-TripwireNotice "[$step/$totalSteps] Watch and score" -Kind Heading

    if (-not $Demo) {
        $baseline = Get-TripwireBaseline -WarningAction SilentlyContinue
        if ($null -eq $baseline) {
            Write-TripwireNotice 'There is no tenant baseline, so "unusual origin" and "off hours" have no meaning yet: both signals will be withheld and every trip marked degraded.' -Kind Attention -Indent 1
            if ($interactive) {
                Write-TripwireNotice 'Building one reads 30 days of sign-in logs. It writes nothing to the tenant.' -Kind Detail -Indent 1
                $build = Read-Host '  Build the baseline now? [Y/n]'
                if ([string]::IsNullOrWhiteSpace($build) -or $build.Trim() -match '^[Yy]') {
                    Get-TripwireBaseline -Build -Days 30 -Save | Out-Null
                    Write-TripwireNotice 'Baseline built and saved.' -Kind Ok -Indent 1
                }
                else {
                    Write-TripwireNotice 'Skipped. Scores in this run are a floor, not a measurement.' -Kind Attention -Indent 1
                }
            }
            else {
                Write-TripwireNotice 'Get-TripwireBaseline -Build -Days 30 -Save' -Kind Command -Indent 2
            }
        }
    }

    $trips = @(Watch-TripwireActivity -Demo:$Demo -Days $Days)
    $summary = $trips | Get-TripwireSummary -Demo:$Demo

    Write-TripwireNotice "$($summary.Total) scored trip(s): $($summary.High) High, $($summary.Medium) Medium, $($summary.Low) Low, $($summary.Suppressed) suppressed." -Kind Ok -Indent 1
    if ($summary.Degraded -gt 0) {
        Write-TripwireNotice "$($summary.Degraded) of them were scored with a signal withheld. Those confidences are a FLOOR: a withheld signal contributes zero and can only push a score down." -Kind Attention -Indent 1
    }
    Write-TripwireNotice ''

    # --------------------------------------------------------------------- 5. report ----
    $step++
    Write-TripwireNotice "[$step/$totalSteps] Report" -Kind Heading

    $written = $null
    if ($NoReport) {
        Write-TripwireNotice 'Skipped (-NoReport). The trips are on the returned object.' -Kind Detail -Indent 1
    }
    else {
        # Written even when nothing was found. A dated artefact saying "this tenant was
        # checked and here is the coverage" is evidence; its absence is not. The report
        # states the blind-run case in words, so an empty one cannot read as a clean one.

        $label = if ($Demo) { 'synthetic fixtures (demo)' } else { $TenantId }
        $exportArgs = @{ TenantLabel = $label; Demo = [bool]$Demo; Confirm = $false }
        if ($ReportPath) { $exportArgs['Path'] = $ReportPath }
        $written = $trips | Export-TripwireReport @exportArgs

        # Export returns the path it would have used even under -WhatIf, when it writes
        # nothing. Announcing a file that is not there -- and then trying to open it --
        # is the kind of small lie that makes a tool feel untrustworthy.
        if ($written -and -not (Test-Path -LiteralPath $written)) {
            Write-TripwireNotice "No report was written (-WhatIf). It would have gone to $written" -Kind Detail -Indent 1
            $written = $null
        }
        elseif ($written) {
            Write-TripwireNotice "Wrote $written" -Kind Ok -Indent 1
            Write-TripwireNotice 'One self-contained file: no scripts, no fonts, no network. It opens from a USB stick on an isolated workstation.' -Kind Detail -Indent 1

            if ($NoOpen -or $NonInteractive) {
                Write-TripwireNotice 'Not opened: -NoOpen or -NonInteractive.' -Kind Detail -Indent 1
            }
            elseif (Open-TripwireLocalFile -Path $written) {
                Write-TripwireNotice 'Opened in your default browser.' -Kind Detail -Indent 1
            }
            else {
                Write-TripwireNotice 'Could not hand it to a browser from here. Open the path above.' -Kind Detail -Indent 1
            }
        }
    }
    Write-TripwireNotice ''

    # -------------------------------------------------------------------- the verdict ----
    Write-TripwireNotice 'Verdict' -Kind Heading
    $verdictKind = if ($summary.High -gt 0) { 'Alert' } elseif ($summary.Medium -gt 0 -or $summary.Total -eq 0) { 'Attention' } else { 'Ok' }
    Write-TripwireNotice $summary.Verdict -Kind $verdictKind -Indent 1
    Write-TripwireNotice ''
    Write-TripwireNotice 'What to do next' -Kind Heading
    foreach ($s in $summary.NextSteps) {
        Write-TripwireNotice "$($s.Step). $($s.Action)" -Indent 1
        if ($s.Command) { Write-TripwireNotice $s.Command -Kind Command -Indent 3 }
    }
    Write-TripwireNotice ''

    return [pscustomobject]@{
        PSTypeName = 'EntraTripwire.GuidedRun'
        Mode       = $mode
        TenantId   = if ($Demo) { $null } else { $TenantId }
        Days       = $Days
        Readiness  = $readiness
        Trips      = $trips
        Summary    = $summary
        ReportPath = $written
        Planted    = $planted
        Blockers   = @()
    }
}

<#
.SYNOPSIS
    Hand a local file to whatever the desktop uses to open it. Never fails the run.

.DESCRIPTION
    Opening the report is a convenience, so every way it can fail is answered with $false
    and a printed path rather than with an error. A headless Linux session has nothing to
    hand it to, and that is detected before trying rather than discovered as an exception.

    Invoke-Item, deliberately: it asks the desktop to open a file. Nothing in this module
    launches a process of its own choosing, and tests/Safety.Tests.ps1 enforces that.
#>
function Open-TripwireLocalFile {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Path)

    if (-not $IsWindows -and -not $IsMacOS) {
        if ([string]::IsNullOrEmpty($env:DISPLAY) -and [string]::IsNullOrEmpty($env:WAYLAND_DISPLAY)) {
            return $false
        }
    }

    try {
        Invoke-Item -LiteralPath $Path -ErrorAction Stop
        return $true
    }
    catch {
        Write-TripwireLog -Message "Could not open $Path : $($_.Exception.Message)"
        return $false
    }
}

Update-TypeData -TypeName 'EntraTripwire.GuidedRun' `
    -DefaultDisplayPropertySet 'Mode', 'TenantId', 'Days', 'ReportPath' -Force
