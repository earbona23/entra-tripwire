<#
.SYNOPSIS
    Collect every touch on a decoy in a time window and return scored trips.

.DESCRIPTION
    Two log sources, because the two interesting behaviours look different:

      Sign-in logs        somebody is USING a decoy credential. The principal that signed
                          in is itself a decoy.
      Directory audits    somebody READ, listed or modified a decoy object. Enumeration
                          precedes use, and this is where it shows up first.

    Records are normalised into touches, correlated per actor, and scored. Output is trips
    sorted by confidence -- including suppressed ones, which stay visible with their reason
    attached. A suppression rule that hides evidence is indistinguishable from a bug that
    loses it.

    The two sources are collected differently, and the difference is the whole reason this
    command can be trusted on a busy tenant:

      * Sign-ins are NARROWED SERVER-SIDE. The decoy inventory is local and known, so the
        query names the decoy identities and Graph returns the few records that matter.
        When any decoy cannot be named in a filter -- no object id, no application id, no
        UPN -- the narrowing is abandoned for the whole source and the window is read in
        full, because a filter that omits one decoy is a blind spot with no symptom.
      * Directory audits CANNOT be narrowed. Graph's $filter over targetResources does not
        express "any of these N objects", and a filter that approximates it would silently
        drop a decoy. They are read by time window instead, and a window that hits the page
        limit is bisected until it reads completely.

    What this command will not do is imply it read a window it did not. Windows that stay
    unreadable are named, and -- unless -AcceptPartialRead is passed -- reported as an
    ERROR after the trips, not as one more line of log. A run that found nothing because it
    read nothing looks exactly like a quiet tenant, and that is the one answer a detector
    must never give by accident.

    -Demo runs the whole path against synthetic fixtures that ship inside the module: no
    tenant, no credentials, no network. It is the intended first five minutes with this tool.

.PARAMETER Demo
    Score the shipped fixtures instead of a tenant.

.PARAMETER Days
    How far back to read. Entra directory audit retention is typically 30 days.

.PARAMETER Decoy
    Decoy inventory. Defaults to the profile inventory (or the demo one under -Demo).

.PARAMETER Baseline
    Tenant baseline. Defaults to the profile baseline (or the demo one under -Demo).

.PARAMETER Policy
    Scoring policy. Defaults to Get-TripwirePolicy.

.PARAMETER MaxPagesPerWindow
    How many pages one time window may take before it is treated as too dense to read in
    one request chain and bisected. Default 200, which is what the single unbounded read
    used to allow.

.PARAMETER MinWindowMinutes
    The floor on bisection. Default 5.

.PARAMETER AcceptPartialRead
    Report an incompletely read window as a warning instead of an error. The trips found
    are returned either way; this only decides how loudly the gap in them is announced.
    Pass it when a partial view is genuinely what you want -- a spot check on a huge
    window -- and not to make the message go away.

.EXAMPLE
    Watch-TripwireActivity -Demo | Format-Table Confidence, Band, DecoyName, ActorLabel, DistinctDecoys

.EXAMPLE
    Watch-TripwireActivity -Days 1 | Where-Object Band -eq 'High'
#>
function Watch-TripwireActivity {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [switch] $Demo,

        # A zero or negative window puts the Graph $filter in the future, so the query
        # returns nothing and the run reports no touches. That is indistinguishable from a
        # quiet tenant, which is the one answer a detector must never give by accident.
        [ValidateRange(1, 365)] [int] $Days = 1,
        [object[]] $Decoy,
        [AllowNull()] $Baseline,
        $Policy,
        [switch] $AcceptPartialRead,

        # How many pages one time window may take before it is declared too dense to read
        # in one go and bisected. This used to be hardcoded at 200 with no way to see it,
        # which is also how a page limit turns into unread log. Lower it on a very busy
        # tenant: a cheaper probe makes the bisection cheaper, and the records are read
        # either way.
        [ValidateRange(1, 10000)] [int] $MaxPagesPerWindow = 200,

        # The floor on bisection. A window this short that still fills every page is
        # reported as unread rather than halved forever.
        [ValidateRange(1, 1440)] [int] $MinWindowMinutes = 5
    )

    $Policy = Resolve-TripwirePolicy -Policy $Policy
    if (-not $Decoy) { $Decoy = @(Get-TripwireDecoy -Demo:$Demo) }
    if (-not $PSBoundParameters.ContainsKey('Baseline')) { $Baseline = Get-TripwireBaseline -Demo:$Demo }

    if (@($Decoy).Count -eq 0) {
        Write-TripwireLog -Level 'Warn' -Message 'The decoy inventory is empty, so no touch can ever be detected. This is a blind run, not a quiet tenant. Plant decoys with New-TripwireDecoy.'
        return
    }

    $index = Get-TripwireDecoyIndex -Decoy $Decoy
    $unread = @()

    if ($Demo) {
        $signIns = @(Read-TripwireJsonFile -Path (Get-TripwireDemoPath -Name 'signins.json'))
        $audits = @(Read-TripwireJsonFile -Path (Get-TripwireDemoPath -Name 'directoryaudits.json'))
    }
    else {
        $until = [DateTime]::UtcNow
        $since = $until.AddDays(-$Days)
        $reads = [System.Collections.Generic.List[object]]::new()

        # SIGN-INS, narrowed server-side from the local inventory. Several queries rather
        # than one: the clauses are grouped by field so that no OR group mixes a GUID
        # column with a string one, which is the shape most likely to be rejected.
        $target = Get-TripwireDecoyFilterGroup -Decoy $Decoy
        $signIns = $null
        if ($target.Complete) {
            $before = $reads.Count
            try {
                $collected = [System.Collections.Generic.List[object]]::new()
                $seenIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($group in $target.Groups) {
                    $read = Read-TripwireLogWindow -Path '/v1.0/auditLogs/signIns' -TimeField 'createdDateTime' `
                        -Since $since -Until $until -Clause $group `
                        -MaxPagesPerWindow $MaxPagesPerWindow -MinWindowMinutes $MinWindowMinutes
                    $reads.Add($read)
                    foreach ($record in $read.Records) {
                        # One record can satisfy two groups -- its userId and its UPN are
                        # both decoy keys -- and the same record twice is the same touch
                        # twice in the report.
                        $id = [string]$record.id
                        if ([string]::IsNullOrWhiteSpace($id) -or $seenIds.Add($id)) { $collected.Add($record) }
                    }
                }
                $signIns = $collected.ToArray()
                Write-TripwireLog -Message "Sign-in log read with a server-side filter naming $(@($Decoy).Count) decoy identit(ies) across $(@($target.Groups).Count) quer(ies)."
            }
            catch {
                # Narrowing is an optimisation. An optimisation that fails must not take
                # the detection with it, so the whole source falls back to the broad read
                # -- and the partial accounting from the failed attempt is dropped, since
                # windows it claimed to have read completely were never matched against.
                if ($reads.Count -gt $before) { $reads.RemoveRange($before, $reads.Count - $before) }
                $signIns = $null
                Write-TripwireLog -Level 'Warn' -Message "The targeted sign-in query failed ($($_.Exception.Message)). Falling back to reading the whole sign-in log for the window and matching locally."
            }
        }
        else {
            Write-TripwireLog -Level 'Warn' -Message "The sign-in log cannot be narrowed server-side: $($target.Reason) Reading the whole window instead, which is slower but complete."
        }

        if ($null -eq $signIns) {
            $read = Read-TripwireLogWindow -Path '/v1.0/auditLogs/signIns' -TimeField 'createdDateTime' `
                -Since $since -Until $until -MaxPagesPerWindow $MaxPagesPerWindow -MinWindowMinutes $MinWindowMinutes
            $reads.Add($read)
            $signIns = $read.Records
        }

        # Directory audits are fetched by time window and matched client-side. Graph's
        # $filter on targetResources is too limited to express "any of these N objects",
        # and building a server-side filter that silently drops a decoy would be worse
        # than reading a few more pages. What the window read buys here is the accounting:
        # a span too dense to read in one go is split rather than cut off.
        $auditRead = Read-TripwireLogWindow -Path '/v1.0/auditLogs/directoryAudits' -TimeField 'activityDateTime' `
            -Since $since -Until $until -MaxPagesPerWindow $MaxPagesPerWindow -MinWindowMinutes $MinWindowMinutes
        $reads.Add($auditRead)
        $audits = $auditRead.Records

        $unread = @($reads | ForEach-Object { $_.IncompleteWindows } | Where-Object { $_ })
    }

    $touches = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $signIns) {
        if ($null -eq $r) { continue }
        $t = ConvertTo-TripwireTouchFromSignIn -Record $r -DecoyIndex $index
        if ($null -ne $t) { $touches.Add($t) }
    }
    foreach ($r in $audits) {
        if ($null -eq $r) { continue }
        $t = ConvertTo-TripwireTouchFromAudit -Record $r -DecoyIndex $index
        if ($null -ne $t) { $touches.Add($t) }
    }

    Write-TripwireLog -Message "$(@($signIns).Count) sign-in and $(@($audits).Count) audit records read; $($touches.Count) touched a decoy."

    if ($touches.Count -gt 0) {
        Invoke-TripwireAnalysis -Touch $touches.ToArray() -Decoy $Decoy -Baseline $Baseline -Policy $Policy |
            Sort-Object -Property Confidence -Descending
    }

    # Deliberately after the output and deliberately NOT inside the touches test above: a
    # run that read nothing and found nothing is the exact case where this has to be said.
    # Zero touches from an unread window is not a quiet tenant, and the operator's only
    # clue that it was not is this message.
    if (@($unread).Count -gt 0) {
        $message = ("This run did not read its whole window. {0} time window(s) still hold unread records, so a decoy touch inside them is NOT in this result: {1}. Re-run over those windows with a shorter -Days." -f `
                @($unread).Count, (@($unread) -join ', '))
        if ($AcceptPartialRead) {
            Write-TripwireLog -Level 'Warn' -Message "$message -AcceptPartialRead was passed, so this is a warning and not an error."
        }
        else {
            Write-Error -Message $message -Category LimitsExceeded -ErrorId 'TripwireIncompleteRead'
        }
    }
}
