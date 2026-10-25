<#
.SYNOPSIS
    Build, load or inspect the tenant baseline the scoring engine compares against.

.DESCRIPTION
    The baseline is what turns "a sign-in from Latvia" into evidence or into Tuesday. It
    holds four things, all derived from the tenant's own sign-in history:

      countries / asns   how often the tenant signs in from each country and autonomous
                         system, so 'unusual' means unusual HERE
      hourHistogram      24 buckets of sign-in volume, so 'off hours' means off hours for
                         this tenant rather than for an assumed office
      actorLastSeen      each principal's last known position, for impossible travel
      suppressedActors   operator-maintained allowlist of the tenant's own scanners

    Without a baseline the engine does not guess: the origin and off-hours signals are
    WITHHELD and every trip is marked degraded. That is the honest behaviour and it is
    visible in the report, rather than a quiet zero that reads as "nothing unusual".

.PARAMETER Build
    Query the tenant's sign-in logs and construct a new baseline.

.PARAMETER Days
    How far back to build from. 30 days is the default; Entra retains sign-in logs for 30
    days on most licences, so asking for more usually returns less than you think.

.PARAMETER Demo
    Load the synthetic baseline shipped with the module.

.PARAMETER Save
    Write the built baseline to the profile state file.

.EXAMPLE
    Get-TripwireBaseline -Build -Days 30 -Save

.EXAMPLE
    (Get-TripwireBaseline -Demo).countries
#>
function Get-TripwireBaseline {
    [CmdletBinding(DefaultParameterSetName = 'Load')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(ParameterSetName = 'Build', Mandatory)] [switch] $Build,
        # Same reason as Watch-TripwireActivity: a non-positive window silently builds a
        # baseline from zero records, and a zero baseline withholds two of the four signals
        # on every trip from then on.
        [Parameter(ParameterSetName = 'Build')] [ValidateRange(1, 365)] [int] $Days = 30,
        [Parameter(ParameterSetName = 'Build')] [switch] $Save,
        [Parameter(ParameterSetName = 'Load')] [switch] $Demo,
        [Parameter(ParameterSetName = 'Load')] [string] $Path
    )

    if ($PSCmdlet.ParameterSetName -eq 'Load' -or -not $Build) {
        if (-not $Path) {
            $Path = if ($Demo) { Get-TripwireDemoPath -Name 'baseline.json' } else { Get-TripwireStatePath -Name 'baseline.json' }
        }
        $loaded = Read-TripwireJsonFile -Path $Path
        if ($null -eq $loaded) {
            Write-TripwireLog -Level 'Warn' -Message "No baseline at $Path. Origin and off-hours signals will be WITHHELD and every trip marked degraded. Run Get-TripwireBaseline -Build -Save."
        }
        elseif (-not $Demo) {
            # Said at load time, against the clock, because this is the moment the operator
            # is looking. The scoring engine asks the same question again per touch and
            # against the touch's own time, which is the one that decides whether a signal
            # is withheld; the default policy is used here because loading a baseline is not
            # a scoring call and carries no -Policy.
            #
            # Skipped for -Demo: those fixtures are deliberately frozen in 2026-06, so an
            # age measured against today's date would be an artefact of the calendar rather
            # than a fact about a tenant.
            $freshness = Test-TripwireBaselineFreshness -Baseline $loaded -AsOf $null -Policy (Get-TripwirePolicy)
            if ($freshness.Stale) {
                Write-TripwireLog -Level 'Warn' -Message "The baseline at $Path is NOT usable as it stands: $($freshness.Reason) Origin and off-hours will be WITHHELD and every trip marked degraded until it is rebuilt."
            }
            elseif ($freshness.Warn) {
                Write-TripwireLog -Level 'Warn' -Message ("The baseline at {0} is {1:N1} day(s) old. It is still being used, but 'unusual country' and 'outside working hours' are measured against the tenant as it was then. Rebuild it with Get-TripwireBaseline -Build -Save." -f $Path, $freshness.AgeDays)
            }
        }
        return $loaded
    }

    $since = [DateTime]::UtcNow.AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $uri = "/v1.0/auditLogs/signIns?`$top=999&`$filter=createdDateTime ge $since"
    Write-TripwireLog -Message "Building baseline from sign-ins since $since"
    $records = @(Invoke-TripwireGraphRequest -Uri $uri -MaxPages 200)

    $countries = @{}
    $asns = @{}
    $hours = @(0) * 24
    $lastSeen = @{}

    $undated = 0

    foreach ($r in $records) {
        # Only successful interactive sign-ins describe where the tenant actually works.
        # Failures describe where it is being attacked from, and folding those into the
        # baseline would teach the detector that the attacker's country is normal.
        if ($null -eq $r.status -or [int]$r.status.errorCode -ne 0) { continue }

        # A record with no usable date cannot go in the hour histogram -- and must not
        # take the rest of the baseline down with it, which an unguarded parse did.
        # It is counted and reported, never silently discarded.
        $when = ConvertTo-TripwireUtcOrNull $r.createdDateTime
        if ($null -eq $when) { $undated++; continue }
        $hours[$when.Hour] += 1

        $c = if ($null -ne $r.location) { [string]$r.location.countryOrRegion } else { '' }
        if (-not [string]::IsNullOrWhiteSpace($c)) {
            if (-not $countries.ContainsKey($c)) { $countries[$c] = 0 }
            $countries[$c] += 1
        }

        $a = [string]$r.autonomousSystemNumber
        if (-not [string]::IsNullOrWhiteSpace($a)) {
            if (-not $asns.ContainsKey($a)) { $asns[$a] = 0 }
            $asns[$a] += 1
        }

        $uid = [string]$r.userId
        if (-not [string]::IsNullOrWhiteSpace($uid) -and $null -ne $r.location -and $null -ne $r.location.geoCoordinates) {
            $prev = $lastSeen[$uid]
            $prevAt = if ($null -ne $prev) { ConvertTo-TripwireUtcOrNull $prev.timestamp } else { $null }
            if ($null -eq $prev -or $null -eq $prevAt -or $prevAt -lt $when) {
                $lastSeen[$uid] = @{
                    timestamp = $when.ToString('o')
                    country   = $c
                    latitude  = $r.location.geoCoordinates.latitude
                    longitude = $r.location.geoCoordinates.longitude
                }
            }
        }
    }

    $baseline = [pscustomobject]@{
        generatedAt      = [DateTime]::UtcNow.ToString('o')
        windowDays       = $Days
        totalSignIns     = ($hours | Measure-Object -Sum).Sum
        countries        = $countries
        asns             = $asns
        hourHistogram    = $hours
        actorLastSeen    = $lastSeen
        suppressedActors = @()
    }

    if ($undated -gt 0) {
        Write-TripwireLog -Level 'Warn' -Message "$undated successful sign-in(s) carried no usable timestamp and are not in the hour histogram. The off-hours signal is calibrated on the rest."
    }

    if ([int]$baseline.totalSignIns -eq 0) {
        Write-TripwireLog -Level 'Warn' -Message 'The baseline contains zero successful sign-ins. This is NOT a quiet tenant -- it usually means the query returned nothing (missing AuditLog.Read.All, or no Entra ID P1/P2 licence, which sign-in log retention requires). Do not save it.'
    }

    if ($Save) {
        $out = Get-TripwireStatePath -Name 'baseline.json'
        $baseline | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $out -Encoding utf8
        Write-TripwireLog -Message "Baseline saved to $out ($($baseline.totalSignIns) sign-ins)."
    }

    return $baseline
}
