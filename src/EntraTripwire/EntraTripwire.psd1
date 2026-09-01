@{
    RootModule        = 'EntraTripwire.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b6f0d3a1-5c72-4e19-9a84-3d1e7c0b25af'

    Author            = 'Eduard Arbona'
    CompanyName       = 'Unknown'
    Copyright         = '(c) 2026 Eduard Arbona. Released under the MIT licence.'

    Description       = 'Deception-based intrusion detection for Microsoft Entra ID. Plants decoy identities, application registrations and credentials that no legitimate process should ever touch, watches Microsoft Graph sign-in and directory audit logs for contact with them, and scores every touch through a calibrated false-positive suppression engine before it reaches a human. Optional containment is dry-run by default and never acts on a degraded or low-confidence signal.'

    PowerShellVersion = '7.2'

    # No RequiredModules on purpose. The module must import and run its whole detection
    # and scoring path in DEMO mode with zero dependencies installed; Microsoft Graph is
    # only needed the moment you connect a real tenant, so Microsoft.Graph.Authentication
    # is loaded lazily by Connect-EntraTripwire with an actionable error if it is absent.
    # A hard RequiredModules entry would make "try it against the fixtures" an install.

    FunctionsToExport = @(
        'Connect-EntraTripwire'
        'Disconnect-EntraTripwire'
        'Enable-TripwirePro'
        'Export-TripwireReport'
        'Get-TripwireBaseline'
        'Get-TripwireDecoy'
        'Get-TripwireLicense'
        'Get-TripwirePolicy'
        'Invoke-TripwireAnalysis'
        'Invoke-TripwireContainment'
        'Measure-TripwireConfidence'
        'New-TripwireDecoy'
        'Remove-TripwireDecoy'
        'Watch-TripwireActivity'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Entra', 'EntraID', 'AzureAD', 'MicrosoftGraph', 'Security', 'Deception', 'Honeytoken', 'Honeypot', 'DetectionEngineering', 'IncidentResponse', 'BlueTeam', 'PSEdition_Core')
            LicenseUri   = 'https://github.com/earbona23/entra-tripwire/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/earbona23/entra-tripwire'
            ReleaseNotes = 'https://github.com/earbona23/entra-tripwire/blob/main/CHANGELOG.md'
        }
    }
}
