<#
.SYNOPSIS
    End the Graph session and clear local session state.
#>
function Disconnect-EntraTripwire {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($PSCmdlet.ShouldProcess('Microsoft Graph', 'Disconnect')) {
        if (Get-Module -Name 'Microsoft.Graph.Authentication') {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        $script:TripwireSession = $null
        Write-TripwireLog -Message 'Disconnected.'
    }
}
