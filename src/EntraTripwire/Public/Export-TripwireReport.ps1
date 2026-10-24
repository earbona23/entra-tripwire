<#
.SYNOPSIS
    Write scored trips to a self-contained HTML report, JSON, or a SIEM-ready JSONL stream.

.DESCRIPTION
    Html and Json are free. Jsonl and -WebhookUri are the SOAR path and require the 'soar'
    Pro feature.

    Whatever the format, the coverage line comes with the findings: how many trips were
    scored with a signal withheld, and how many were suppressed. A quiet report from a
    blind run must not read like a quiet tenant.

.PARAMETER Trip
    Scored trips.

.PARAMETER Path
    Output file. Defaults to a timestamped name in the working directory.

.PARAMETER Format
    Html (default), Json, or Jsonl.

.PARAMETER WebhookUri
    POST each trip as JSON to a SOAR or SIEM ingest endpoint. Pro ('soar').

.PARAMETER TenantLabel
    Free text for the report header.

.EXAMPLE
    Watch-TripwireActivity -Demo | Export-TripwireReport -Path ./demo-report.html
#>
function Export-TripwireReport {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Trip,
        [string] $Path,
        [ValidateSet('Html', 'Json', 'Jsonl')] [string] $Format = 'Html',
        [string] $WebhookUri,
        [string] $TenantLabel = 'unspecified tenant',
        [switch] $Demo
    )

    begin { $collected = [System.Collections.Generic.List[object]]::new() }
    process { $collected.Add($Trip) }

    end {
        if (($Format -eq 'Jsonl' -or $WebhookUri) -and -not (Test-TripwireProFeature -Feature 'soar')) {
            throw "JSONL and webhook delivery need EntraTripwirePro (soar), which is not installed. $((Get-TripwireProvider).Reason) Html and Json exports are free and contain the same data."
        }

        if (-not $Path) {
            $ext = $Format.ToLowerInvariant()
            $Path = Join-Path (Get-Location) ("tripwire-report-{0:yyyyMMdd-HHmmss}.{1}" -f [DateTime]::UtcNow, $ext)
        }

        $trips = @($collected)
        $content = switch ($Format) {
            'Html' { ConvertTo-TripwireHtmlReport -Trip $trips -TenantLabel $TenantLabel -Demo:$Demo }
            'Json' { $trips | ConvertTo-Json -Depth 10 }
            'Jsonl' { ($trips | ForEach-Object { $_ | ConvertTo-Json -Depth 10 -Compress }) -join "`n" }
        }

        if ($PSCmdlet.ShouldProcess($Path, "Write $Format report for $($trips.Count) trip(s)")) {
            Set-Content -LiteralPath $Path -Value $content -Encoding utf8
            $degraded = @($trips | Where-Object { $_.Degraded }).Count
            $suppressed = @($trips | Where-Object { $_.Band -eq 'Suppressed' }).Count
            Write-TripwireLog -Message "Wrote $Path -- $($trips.Count) trips, $degraded scored degraded, $suppressed suppressed."
        }

        if ($WebhookUri) {
            foreach ($t in $trips) {
                if (-not $PSCmdlet.ShouldProcess($WebhookUri, "POST trip $($t.TouchId)")) { continue }
                # Delivery is the paid capability; the outcome is logged here, on the side
                # that owns the audit trail. A failure is reported as a failure: a pipeline
                # that silently drops the one event that mattered is worse than none.
                try {
                    Invoke-TripwireProCapability -Capability 'Webhook' -Arguments @{ Uri = $WebhookUri; Trip = $t }
                    Write-TripwireLog -Message "Delivered trip $($t.TouchId) to the webhook."
                }
                catch {
                    Write-TripwireLog -Level 'Warn' -Message "Webhook delivery FAILED for trip $($t.TouchId): $($_.Exception.Message). This trip was NOT delivered."
                    throw
                }
            }
        }

        return $Path
    }
}
