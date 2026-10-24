<#
.SYNOPSIS
    The one read path to Microsoft Graph. GET only, with paging.

.DESCRIPTION
    Every read in this module goes through here. The function has no -Method parameter and
    no -Body parameter, and the verb is hardcoded at the single call site, so a future
    commit cannot quietly turn a read into a write by passing an argument. Writes have
    their own gateway with an explicit allowlist (Invoke-TripwireGraphWrite); there are
    exactly two ways to reach Graph from this module and both are audited by tests.

    Paging follows @odata.nextLink. On HTTP 429 it honours Retry-After, because a detector
    that gives up halfway through the sign-in log reports fewer touches than happened --
    the failure mode that looks like good news.
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
        [int] $MaxRetry = 4
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

    if ($next) {
        # Truncation is reported, never swallowed. A partial log read that looks complete
        # is how a detector says "nothing happened" about pages it never fetched.
        Write-TripwireLog -Level 'Warn' -Message "Stopped after $MaxPages pages; results are TRUNCATED. Narrow the time window or raise -MaxPages."
    }

    # Enumerated, not comma-wrapped: callers write @(Invoke-TripwireGraphRequest ...), and
    # ,$array there would produce a one-element array holding the whole page set.
    return $results.ToArray()
}
