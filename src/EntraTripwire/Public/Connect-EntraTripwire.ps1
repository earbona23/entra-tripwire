<#
.SYNOPSIS
    Connect to a tenant, requesting only the scopes the chosen mode needs.

.DESCRIPTION
    Consent is derived from intent, not from a fixed block. Watching for touches needs two
    read scopes and nothing else; planting decoys needs the ability to create objects;
    containment needs the ability to disable one. An operator who only wants detection
    should never be asked to consent to writes, and with -Mode Detect they are not.

    Microsoft.Graph.Authentication is loaded here rather than declared in RequiredModules,
    so the module imports and runs its entire detection and scoring path in DEMO mode with
    nothing installed. If it is missing, the error says exactly what to install.

.PARAMETER Mode
    Detect  -- read sign-in and directory audit logs (AuditLog.Read.All, Directory.Read.All)
    Plant   -- Detect, plus create and delete decoy users and application registrations
    Contain -- Plant, plus disable an identity and revoke its sessions

.PARAMETER TenantId
    The tenant to connect to.

.PARAMETER ProfileName
    Names the local state set (decoy inventory, baseline) for this tenant. Anything other
    than 'default' requires the multitenant Pro feature.

.EXAMPLE
    Connect-EntraTripwire -TenantId contoso.onmicrosoft.com -Mode Detect
#>
function Connect-EntraTripwire {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $TenantId,
        [ValidateSet('Detect', 'Plant', 'Contain')] [string] $Mode = 'Detect',
        [string] $ProfileName = 'default'
    )

    # Named profiles keep each tenant's decoy inventory and baseline apart, which is what
    # managing more than one tenant requires: a decoy planted in one tenant must not be
    # looked for in another's sign-in log, and one tenant's baseline must not suppress a
    # touch in another. The isolation is provided by EntraTripwirePro.
    $script:TripwireStateRootOverride = $null
    if ($ProfileName -ne 'default') {
        if (-not (Test-TripwireProFeature -Feature 'multitenant')) {
            throw "Named profiles need EntraTripwirePro (multitenant), which is not installed. $((Get-TripwireProvider).Reason) The free module manages one tenant at a time under the 'default' profile."
        }
        $script:TripwireStateRootOverride = Invoke-TripwireProCapability -Capability 'Profile' -Arguments @{ ProfileName = $ProfileName }
    }

    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        throw "Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser. (It is not needed for DEMO mode: try Watch-TripwireActivity -Demo.)"
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $scopes = switch ($Mode) {
        'Detect' { @('AuditLog.Read.All', 'Directory.Read.All') }
        'Plant' { @('AuditLog.Read.All', 'Directory.Read.All', 'User.ReadWrite.All', 'Application.ReadWrite.OwnedBy') }
        'Contain' { @('AuditLog.Read.All', 'Directory.Read.All', 'User.ReadWrite.All', 'Application.ReadWrite.OwnedBy') }
    }

    Write-TripwireLog -Message "Connecting to $TenantId in $Mode mode with scopes: $($scopes -join ', ')"
    Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome -ErrorAction Stop | Out-Null

    # The signed-in account is recorded so New-TripwireDecoy can stamp plantedBy, which is
    # what the provisioning-grace suppression rule matches on. Without it the first run of
    # every deployment scores its own planting as an intrusion.
    $account = $null
    try { $account = (Get-MgContext).Account } catch { $account = $null }

    $script:TripwireSession = [pscustomobject]@{
        TenantId    = $TenantId
        Account     = $account
        Mode        = $Mode
        ProfileName = $ProfileName
        Scopes      = $scopes
        ConnectedAt = [DateTime]::UtcNow
    }
    return $script:TripwireSession
}
