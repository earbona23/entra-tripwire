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
        [int] $Days = 1,
        [object[]] $Decoy,
        [AllowNull()] $Baseline,
        $Policy
    )

    if (-not $Policy) { $Policy = Get-TripwirePolicy }
    if (-not $Decoy) { $Decoy = @(Get-TripwireDecoy -Demo:$Demo) }
    if (-not $PSBoundParameters.ContainsKey('Baseline')) { $Baseline = Get-TripwireBaseline -Demo:$Demo }

    if (@($Decoy).Count -eq 0) {
        Write-TripwireLog -Level 'Warn' -Message 'The decoy inventory is empty, so no touch can ever be detected. This is a blind run, not a quiet tenant. Plant decoys with New-TripwireDecoy.'
        return
    }

    $index = Get-TripwireDecoyIndex -Decoy $Decoy

    if ($Demo) {
        $signIns = @(Read-TripwireJsonFile -Path (Get-TripwireDemoPath -Name 'signins.json'))
        $audits = @(Read-TripwireJsonFile -Path (Get-TripwireDemoPath -Name 'directoryaudits.json'))
    }
    else {
        $since = [DateTime]::UtcNow.AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $signIns = @(Invoke-TripwireGraphRequest -Uri "/v1.0/auditLogs/signIns?`$top=999&`$filter=createdDateTime ge $since" -MaxPages 200)
        # Directory audits are fetched by time window and matched client-side. Graph's
        # $filter on targetResources is too limited to express "any of these N objects",
        # and building a server-side filter that silently drops a decoy would be worse
        # than reading a few more pages.
        $audits = @(Invoke-TripwireGraphRequest -Uri "/v1.0/auditLogs/directoryAudits?`$top=999&`$filter=activityDateTime ge $since" -MaxPages 200)
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

    Write-TripwireLog -Message "$($signIns.Count) sign-in and $($audits.Count) audit records read; $($touches.Count) touched a decoy."

    if ($touches.Count -eq 0) { return }

    Invoke-TripwireAnalysis -Touch $touches.ToArray() -Decoy $Decoy -Baseline $Baseline -Policy $Policy |
        Sort-Object -Property Confidence -Descending
}
