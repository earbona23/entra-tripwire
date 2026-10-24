@{
    RootModule        = 'EntraTripwire.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b6f0d3a1-5c72-4e19-9a84-3d1e7c0b25af'

    Author            = 'Eduard Arbona'
    CompanyName       = 'ArrankaGo LLC'
    Copyright         = '(c) 2026 Eduard Arbona. Released under the MIT licence.'

    Description       = 'Detects an intruder who is already inside a Microsoft Entra ID tenant. Plants decoy users, application registrations and client secrets that no legitimate process should ever touch, watches the Microsoft Graph sign-in and directory audit logs for contact with them, and scores every touch through a calibrated false-positive suppression engine before it reaches a human, so a deception deployment does not page its operator into switching it off. Answers "is someone in here right now?", which is a different question from "how could someone get in". Runs with no dependency and no tenant in DEMO mode against fixtures shipped inside the module; Microsoft.Graph.Authentication is loaded lazily and is only needed to connect a real tenant. Optional containment is dry-run by default, requires a High and non-degraded confidence band, and never acts on a signal it could not fully evaluate.'

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
            # Platform tags put the package into the Gallery's search filters. Only Windows
            # and Linux are claimed: both are proven by CI on every push. macOS is not
            # tested, so it is not tagged.
            Tags         = @('Entra', 'EntraID', 'AzureAD', 'MicrosoftGraph', 'Microsoft365', 'Security', 'Deception', 'Honeytoken', 'Honeypot', 'ThreatDetection', 'DetectionEngineering', 'IncidentResponse', 'BlueTeam', 'PSEdition_Core', 'Windows', 'Linux')
            LicenseUri   = 'https://github.com/earbona23/entra-tripwire/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/earbona23/entra-tripwire'

            # The Gallery renders this field as the release notes themselves, not as a link,
            # so a bare URL here shows a reader a URL where they expected to read what
            # changed. Summary first, link second.
            ReleaseNotes = '1.0.0 - First release. Decoy planting (users, application registrations, client secrets), detection across the sign-in and directory audit logs, the four-signal confidence engine with suppression and withheld-signal tracking, tenant baselining with impossible-travel detection, the containment plan, the self-contained HTML report, and DEMO mode against shipped fixtures. Full history: https://github.com/earbona23/entra-tripwire/blob/main/CHANGELOG.md'
        }
    }
}
