<#
.SYNOPSIS
    Plant a decoy identity or application registration, and record it in the inventory.

.DESCRIPTION
    A decoy only works if it is worth finding and impossible to reach by accident. This
    function creates it deliberately inert:

      * The decoy user is created with a random password that is generated, sent to Graph,
        and then discarded. It is never returned, never stored, and nobody -- including the
        operator -- can sign in as it. The bait is the OBJECT, not a usable credential.
      * No group membership, no licence, no directory role, no API permission is granted.
        That is not a promise: Invoke-TripwireGraphWrite has no allowlist entry that could
        grant any of them, and tests/Safety.Tests.ps1 fails the build if one appears.
      * Nothing about the object marks it as a decoy in the directory. The only record is
        the local inventory.

    -WithSecret is the one case where a usable credential is produced: a client secret on
    a decoy application that holds no permissions, returned once so you can seed it where
    an intruder will find it (a fake config file, a stale wiki page, a credential-manager
    entry). Because the application has no permissions, the secret grants nothing -- its
    only function is to be used, and be seen being used.

.PARAMETER Type
    User or Application.

.PARAMETER DisplayName
    Choose something that looks like it belongs. 'svc-backup-archive' gets found;
    'DECOY_DO_NOT_USE' gets skipped. See docs/deception-design.md.

.PARAMETER UserPrincipalName
    Required for -Type User.

.PARAMETER RegisterOnly
    Record an object that already exists as a decoy, without creating anything. No tenant
    write happens at all. Use this when the object was planted by hand or by another team.

.PARAMETER ObjectId
    The directory object id. Required with -RegisterOnly.

.PARAMETER WithSecret
    Application only. Add a client secret and return its value once.

.PARAMETER Note
    Free text recorded with the decoy, e.g. where its credential was seeded.

.EXAMPLE
    New-TripwireDecoy -Type User -DisplayName 'svc-backup-archive' -UserPrincipalName 'svc-backup-archive@contoso.com' -WhatIf

.EXAMPLE
    New-TripwireDecoy -Type Application -DisplayName 'Legacy VPN Connector' -WithSecret
#>
function New-TripwireDecoy {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidateSet('User', 'Application')] [string] $Type,
        [Parameter(Mandatory)] [string] $DisplayName,
        [string] $UserPrincipalName,
        [switch] $RegisterOnly,
        [string] $ObjectId,
        [switch] $WithSecret,
        [string] $Note = '',
        [string] $Path
    )

    if ($Type -eq 'User' -and -not $RegisterOnly -and [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        throw 'A decoy user needs -UserPrincipalName.'
    }
    if ($RegisterOnly -and [string]::IsNullOrWhiteSpace($ObjectId)) {
        throw '-RegisterOnly needs the -ObjectId of the object that already exists.'
    }
    if ($WithSecret -and $Type -ne 'Application') {
        throw '-WithSecret applies to -Type Application only.'
    }

    if (-not $Path) { $Path = Get-TripwireStatePath -Name 'decoys.json' }

    $record = [ordered]@{
        id                 = 'decoy-' + [Guid]::NewGuid().ToString('n').Substring(0, 12)
        type               = $Type
        objectId           = $ObjectId
        appId              = $null
        displayName        = $DisplayName
        upn                = $UserPrincipalName
        plantedAt          = [DateTime]::UtcNow.ToString('o')
        plantedBy          = if ($script:TripwireSession -and $script:TripwireSession.Account) { $script:TripwireSession.Account } else { $env:USER }
        legitimateUseCount = 0
        note               = $Note
    }
    $secretValue = $null

    if (-not $RegisterOnly) {
        $target = "$Type '$DisplayName'"
        if ($PSCmdlet.ShouldProcess($target, 'Create a decoy object in the tenant')) {
            if ($Type -eq 'User') {
                # Generated, sent, discarded. Never returned to the caller and never stored.
                $bytes = [byte[]]::new(30)
                [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
                $throwaway = 'Aa1!' + [Convert]::ToBase64String($bytes)

                $created = Invoke-TripwireGraphWrite -Method POST -Path '/v1.0/users' -Body @{
                    accountEnabled    = $true
                    displayName       = $DisplayName
                    mailNickname      = ($UserPrincipalName -split '@')[0]
                    userPrincipalName = $UserPrincipalName
                    passwordProfile   = @{ password = $throwaway; forceChangePasswordNextSignIn = $false }
                }
                $record['objectId'] = [string]$created.id
                Remove-Variable -Name throwaway -ErrorAction SilentlyContinue
            }
            else {
                $created = Invoke-TripwireGraphWrite -Method POST -Path '/v1.0/applications' -Body @{
                    displayName = $DisplayName
                }
                $record['objectId'] = [string]$created.id
                $record['appId'] = [string]$created.appId

                if ($WithSecret) {
                    $cred = Invoke-TripwireGraphWrite -Method POST -Path "/v1.0/applications/$($created.id)/addPassword" -Body @{
                        passwordCredential = @{ displayName = 'tripwire' }
                    }
                    $secretValue = [string]$cred.secretText
                }
            }
        }
        else {
            Write-TripwireLog -Message 'WhatIf: no object was created; the inventory was not written.'
            return [pscustomobject]$record
        }
    }

    $existing = @(Get-TripwireDecoy -Path $Path)
    $all = @($existing) + @([pscustomobject]$record)
    @{ version = 1; decoys = $all } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding utf8
    Write-TripwireLog -Message "Decoy $($record.id) recorded in $Path"

    $out = [pscustomobject]$record
    if ($secretValue) {
        # Returned once, on the object, never written to the inventory. If it is lost,
        # plant another decoy -- there is nothing of value behind it.
        $out | Add-Member -NotePropertyName 'SecretValueShownOnce' -NotePropertyValue $secretValue
    }
    return $out
}
