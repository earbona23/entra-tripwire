<#
.SYNOPSIS
    POST one trip to an operator-supplied SOAR or SIEM ingest endpoint.

.DESCRIPTION
    Isolated in its own function for two reasons. It is the only outbound network call in
    the module that is not Microsoft Graph, so it is easy to audit and easy to mock; and a
    delivery failure must be reported as a delivery failure rather than swallowed. An
    alerting pipeline that silently drops the one event that mattered is worse than no
    pipeline, because it is believed.

    The destination is always supplied by the caller. Nothing in this module has a default
    endpoint, and no telemetry of any kind is emitted.
#>
function Send-TripwireWebhook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] $Trip
    )

    try {
        Invoke-RestMethod -Method POST -Uri $Uri -ContentType 'application/json' `
            -Body ($Trip | ConvertTo-Json -Depth 10 -Compress) -ErrorAction Stop | Out-Null
        Write-TripwireLog -Message "Delivered trip $($Trip.TouchId) to the webhook."
    }
    catch {
        Write-TripwireLog -Level 'Warn' -Message "Webhook delivery FAILED for trip $($Trip.TouchId): $($_.Exception.Message). This trip was NOT delivered."
        throw
    }
}
