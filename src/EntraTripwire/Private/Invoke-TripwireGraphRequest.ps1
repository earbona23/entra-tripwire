<#
.SYNOPSIS
    The one read path to Microsoft Graph. GET only, with paging.

.DESCRIPTION
    Every read in this module goes through here. The function has no -Method parameter and
    no request-content parameter, and the verb is hardcoded at the single call site, so a
    future commit cannot quietly turn a read into a write by passing an argument. Writes
    have their own gateway with an explicit allowlist (Invoke-TripwireGraphWrite); there are
    exactly two ways to reach Graph from this module and both are audited by tests.

    Paging follows @odata.nextLink. On HTTP 429 it honours Retry-After, because a detector
    that gives up halfway through the sign-in log reports fewer touches than happened --
    the failure mode that looks like good news.

    Truncation is reported twice over, on purpose: as a warning for the human, and as a
    [ref] flag for the caller. Read-TripwireLogWindow below uses the flag to halve the time
    window and read again, which is how the same page limit stops meaning "some of your
    log is unread". A warning cannot be branched on without matching its text, and code
    that depends on the wording of a log line breaks the first time somebody rewords it.
#>
function Invoke-TripwireGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Uri,

        # MaxPages 0 would fetch nothing and report success. Truncation is already warned
        # about; fetching no pages at all must not even be expressible.
        [ValidateRange(1, 10000)]
        [int] $MaxPages = 50,

        [ValidateRange(0, 10)]
        [int] $MaxRetry = 4,

        # Set to $true when the read stopped at the page limit with pages still to fetch,
        # and to $false when it ran to the end. Always assigned when supplied: leaving it
        # untouched on a complete read would make a stale $true from a previous call read
        # as this call's verdict.
        [AllowNull()]
        [ref] $Truncated
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 0

    while ($next -and $page -lt $MaxPages) {
        $page++
        $attempt = 0
        $response = $null

        while ($true) {
            $attempt++
            try {
                # GET is hardcoded. This is the only place the module issues a read.
                $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
                break
            }
            catch {
                $status = $null
                if ($null -ne $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }

                if (($status -eq 429 -or $status -ge 500) -and $attempt -le $MaxRetry) {
                    $delay = [Math]::Min([Math]::Pow(2, $attempt), 30)
                    Write-TripwireLog -Level 'Warn' -Message "Graph returned $status for $next; retry $attempt in ${delay}s."
                    Start-Sleep -Seconds $delay
                    continue
                }
                throw "Graph GET failed for '$next': $($_.Exception.Message)"
            }
        }

        if ($null -ne $response.value) { $results.AddRange(@($response.value)) }
        elseif ($null -ne $response) { $results.Add($response) }

        $next = $response.'@odata.nextLink'
    }

    if ($null -ne $Truncated) { $Truncated.Value = [bool] $next }

    if ($next) {
        # Truncation is reported, never swallowed. A partial log read that looks complete
        # is how a detector says "nothing happened" about pages it never fetched.
        Write-TripwireLog -Level 'Warn' -Message "Stopped after $MaxPages pages; results are TRUNCATED. Narrow the time window or raise -MaxPages."
    }

    # Enumerated, not comma-wrapped: callers write @(Invoke-TripwireGraphRequest ...), and
    # ,$array there would produce a one-element array holding the whole page set.
    return $results.ToArray()
}

<#
.SYNOPSIS
    Turn the local decoy inventory into OData clause groups for the sign-in log.

.DESCRIPTION
    The sign-in side of collection does not need the whole log. The inventory is local and
    known, so the query can name the decoy identities server-side and Graph can return the
    handful of records that matter instead of every sign-in in the window. On a busy tenant
    with -Days 30 that is the difference between a few records and a couple of hundred
    thousand -- and the page limit sitting in between them.

    What this function will NOT do is narrow the query in a way that could drop a decoy.
    It reports Complete = $false, with a reason, whenever any decoy in the inventory has
    none of the three identifiers the sign-in matcher compares against, and the caller
    then reads the whole window and matches locally. A filter that omits one decoy is a
    blind spot with no symptom: that decoy simply never trips again.

    The three clause fields mirror ConvertTo-TripwireTouchFromSignIn exactly:

      userId             <- decoy objectId
      appId              <- decoy appId
      userPrincipalName  <- decoy upn, and the decoy displayName

    displayName is filtered for because it is a key in the local index, but it does not
    count as coverage: it leaves `userId eq <displayName>` unexpressed. In real Graph data
    userId and appId are GUIDs and can only ever equal an objectId or an appId, so a decoy
    carrying one of those three is fully expressible; one carrying only a name is not.

    Values are OData-escaped (a quote doubles) and then percent-escaped. Both are needed:
    a guest UPN contains '#', and an unescaped '#' truncates the request URI at the
    fragment, which would silently drop that decoy's clause while the query still succeeds.
#>
function Get-TripwireDecoyFilterGroup {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Decoy,

        # Graph rejects filters past a certain complexity, and a rejected filter costs a
        # fallback to the whole log. Several small queries beat one that might not run.
        [ValidateRange(1, 50)] [int] $MaxClausePerGroup = 15
    )

    $fields = [ordered]@{
        userId            = [System.Collections.Generic.List[string]]::new()
        appId             = [System.Collections.Generic.List[string]]::new()
        userPrincipalName = [System.Collections.Generic.List[string]]::new()
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $uncovered = [System.Collections.Generic.List[string]]::new()

    foreach ($d in $Decoy) {
        if ($null -eq $d) { continue }

        $covered = $false
        foreach ($pair in @(
                @{ Field = 'userId'; Value = $d.objectId }
                @{ Field = 'appId'; Value = $d.appId }
                @{ Field = 'userPrincipalName'; Value = $d.upn }
            )) {
            $value = [string]$pair.Value
            if ([string]::IsNullOrWhiteSpace($value)) { continue }
            $covered = $true
            if ($seen.Add("$($pair.Field)|$value")) { $fields[$pair.Field].Add($value) }
        }

        $name = [string]$d.displayName
        if (-not [string]::IsNullOrWhiteSpace($name) -and $seen.Add("userPrincipalName|$name")) {
            $fields['userPrincipalName'].Add($name)
        }

        if (-not $covered) {
            $label = if (-not [string]::IsNullOrWhiteSpace($name)) { $name } else { [string]$d.id }
            $uncovered.Add($label)
        }
    }

    $groups = [System.Collections.Generic.List[string]]::new()
    foreach ($field in $fields.Keys) {
        $values = @($fields[$field])
        for ($i = 0; $i -lt $values.Count; $i += $MaxClausePerGroup) {
            $take = [Math]::Min($MaxClausePerGroup, $values.Count - $i)
            $clauses = @($values[$i..($i + $take - 1)] | ForEach-Object {
                    "$field eq '$([Uri]::EscapeDataString($_.Replace("'", "''")))'"
                })
            $groups.Add($clauses -join ' or ')
        }
    }

    $reason = ''
    if ($uncovered.Count -gt 0) {
        $reason = ("{0} decoy record(s) carry no object id, application id or UPN, so a server-side filter cannot name them: {1}." -f `
                $uncovered.Count, (@($uncovered) -join ', '))
    }
    elseif ($groups.Count -eq 0) {
        $reason = 'The decoy inventory produced no identifier to filter on.'
    }

    return [pscustomobject]@{
        Complete = ($uncovered.Count -eq 0 -and $groups.Count -gt 0)
        Groups   = $groups.ToArray()
        Reason   = $reason
    }
}

<#
.SYNOPSIS
    Read one Graph log over a time window, and account for what was read completely.

.DESCRIPTION
    The page limit used to be the end of the story: a read that hit it warned and returned
    whatever it had, and the records past it were simply gone from the run. On a quiet
    tenant that never happens; on a busy one it happens with -Days 30 and the result is a
    report that lists fewer touches than occurred.

    This function makes the limit recoverable instead. It reads the window with an explicit
    upper bound, and when Graph says there were more pages it BISECTS the window and reads
    the halves, down to MinWindowMinutes. A window that still truncates at the floor is
    recorded by name in IncompleteWindows, so the caller can state which slices of time it
    could not read rather than implying it read all of them.

    Windows are half-open -- `ge start and lt end` -- so two adjacent slices can neither
    overlap nor leave a gap between them, whatever precision Graph keeps its timestamps at.
    The records of a truncated window are discarded rather than merged with its halves:
    the halves re-read the same span, and merging would double every record in it.

    Completeness is the answer this function exists to produce. It is never inferred from
    the number of records that came back, which is the inference that cannot distinguish a
    quiet window from an unread one.
#>
function Read-TripwireLogWindow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $TimeField,
        [Parameter(Mandatory)] [DateTime] $Since,
        [Parameter(Mandatory)] [DateTime] $Until,

        # ANDed into every window's filter. Empty means the whole log for the window.
        [AllowEmptyString()] [string] $Clause = '',

        [ValidateRange(1, 10000)] [int] $MaxPagesPerWindow = 200,

        # The floor on bisection. 200 pages of 999 records inside five minutes is around
        # 200,000 records in five minutes; a window that still truncates there is not a
        # window this tool can read, and it says so instead of halving forever.
        [ValidateRange(1, 1440)] [int] $MinWindowMinutes = 5,

        # A ceiling on the number of requests one call may issue, so a pathological log
        # cannot turn one run into an unbounded request storm against a tenant.
        [ValidateRange(1, 100000)] [int] $MaxWindows = 2000
    )

    if ($Until -le $Since) {
        # Unreachable from Watch-TripwireActivity, whose -Days is validated 1..365, and it
        # must stay unreachable: an empty window reads nothing and would otherwise be
        # reported as a complete read of it.
        throw ("Read-TripwireLogWindow was asked to read {0} .. {1}, a window that cannot contain anything. A window with no duration reads as a quiet tenant." -f `
                $Since.ToString('o'), $Until.ToString('o'))
    }

    $format = 'yyyy-MM-ddTHH:mm:ssZ'
    $records = [System.Collections.Generic.List[object]]::new()
    $incomplete = [System.Collections.Generic.List[string]]::new()
    $pending = [System.Collections.Generic.Stack[object]]::new()
    $pending.Push([pscustomobject]@{ Start = $Since; End = $Until })
    $windowsRead = 0

    $label = {
        param($w)
        '{0}..{1}' -f $w.Start.ToUniversalTime().ToString($format), $w.End.ToUniversalTime().ToString($format)
    }

    while ($pending.Count -gt 0) {
        if ($windowsRead -ge $MaxWindows) {
            # Everything still queued is unread, and every one of them is named. Stopping
            # quietly here would be the page limit's failure mode one level up.
            while ($pending.Count -gt 0) { $incomplete.Add((& $label $pending.Pop())) }
            Write-TripwireLog -Level 'Warn' -Message "Stopped after $MaxWindows windows on $Path; $($incomplete.Count) window(s) are UNREAD."
            break
        }

        $window = $pending.Pop()
        $windowsRead++

        $filter = "$TimeField ge $($window.Start.ToUniversalTime().ToString($format)) and $TimeField lt $($window.End.ToUniversalTime().ToString($format))"
        if (-not [string]::IsNullOrWhiteSpace($Clause)) { $filter += " and ($Clause)" }

        $truncated = $false
        $page = @(Invoke-TripwireGraphRequest -Uri "$Path`?`$top=999&`$filter=$filter" `
                -MaxPages $MaxPagesPerWindow -Truncated ([ref] $truncated))

        if (-not $truncated) {
            if ($page.Count -gt 0) { $records.AddRange($page) }
            continue
        }

        $span = $window.End - $window.Start
        $mid = $window.Start.AddTicks([long]($span.Ticks / 2))
        if ($span.TotalMinutes -gt $MinWindowMinutes -and $mid -gt $window.Start -and $mid -lt $window.End) {
            Write-TripwireLog -Message "$(& $label $window) on $Path hit the page limit; splitting it and reading both halves."
            $pending.Push([pscustomobject]@{ Start = $mid; End = $window.End })
            $pending.Push([pscustomobject]@{ Start = $window.Start; End = $mid })
            continue
        }

        if ($page.Count -gt 0) { $records.AddRange($page) }
        $incomplete.Add((& $label $window))
    }

    return [pscustomobject]@{
        Records           = $records.ToArray()
        Complete          = ($incomplete.Count -eq 0)
        WindowsRead       = $windowsRead
        IncompleteWindows = $incomplete.ToArray()
    }
}
