#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The guards that make a deception tool safe to run against a production tenant, and safe
    to hand an automated action to.

    Several of these tests read the source rather than call the code. That is deliberate:
    the claim being defended is "there is no code path that does X", and the only way to
    test the absence of a path is to look for it.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'EntraTripwire'
    Import-Module (Join-Path $script:SourceRoot 'EntraTripwire.psd1') -Force
    $script:Module = Get-Module EntraTripwire
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Files = @(Get-ChildItem -Path $script:SourceRoot -Filter '*.ps1' -Recurse -File)
}

Describe 'There are exactly two ways to reach Microsoft Graph' {

    It 'Invoke-MgGraphRequest is called from the read gateway and the write gateway, and nowhere else' {
        $callers = @($script:Files | Where-Object {
                (Get-Content -LiteralPath $_.FullName -Raw) -match 'Invoke-MgGraphRequest'
            } | ForEach-Object { $_.Name } | Sort-Object)

        $callers | Should -Be @('Invoke-TripwireGraphRequest.ps1', 'Invoke-TripwireGraphWrite.ps1')
    }

    It 'the read gateway hardcodes GET and offers no way to choose a verb or send a body' {
        $src = Get-Content -LiteralPath (Join-Path $script:SourceRoot 'Private/Invoke-TripwireGraphRequest.ps1') -Raw
        $src | Should -Match 'Invoke-MgGraphRequest -Method GET'
        $src | Should -Not -Match '\[string\]\s*\$Method'
        $src | Should -Not -Match '\$Body'
    }

    It 'the only non-Graph outbound call in the module is the operator-supplied webhook' {
        $callers = @($script:Files | Where-Object {
                (Get-Content -LiteralPath $_.FullName -Raw) -match 'Invoke-RestMethod|Invoke-WebRequest'
            } | ForEach-Object { $_.Name } | Sort-Object)
        $callers | Should -Be @('Send-TripwireWebhook.ps1')
    }

    It 'no source file contains a network probe aimed at an observed address' {
        # Deception is a defensive technique. Scanning, connecting to or otherwise touching
        # the source of an intrusion is not containment, and none of it belongs here.
        foreach ($f in $script:Files) {
            $src = Get-Content -LiteralPath $f.FullName -Raw
            $src | Should -Not -Match 'Test-NetConnection|Test-Connection|New-Object\s+System\.Net\.Sockets|TcpClient|nmap|Start-Process' `
                -Because "$($f.Name) must not reach out to an address it observed"
        }
    }
}

Describe 'The write allowlist' {

    It 'permits only the eight documented operations' {
        $entries = & $script:Module { $script:TripwireWriteAllowlist }
        @($entries).Count | Should -Be 8
        @($entries | ForEach-Object { $_.Method } | Sort-Object -Unique) | Should -Be @('DELETE', 'PATCH', 'POST')
    }

    It 'can disable an identity and is structurally incapable of enabling one' {
        $entries = & $script:Module { $script:TripwireWriteAllowlist }
        foreach ($e in @($entries | Where-Object { $_.Method -eq 'PATCH' })) {
            $e.ContainsKey('BodyMustEqual') | Should -BeTrue -Because 'an unconstrained PATCH could write anything'
            @($e.BodyMustEqual.Keys) | Should -Be @('accountEnabled')
            $e.BodyMustEqual['accountEnabled'] | Should -BeFalse
        }
    }

    It 'refuses a PATCH that would ENABLE an account' {
        $permit = & $script:Module { Get-TripwireWritePermit -Method 'PATCH' -Path '/v1.0/users/abc' -Body @{ accountEnabled = $true } }
        $permit | Should -BeNullOrEmpty
    }

    It 'refuses a PATCH that smuggles an extra property alongside the permitted one' {
        $permit = & $script:Module { Get-TripwireWritePermit -Method 'PATCH' -Path '/v1.0/users/abc' -Body @{ accountEnabled = $false; passwordProfile = 'x' } }
        $permit | Should -BeNullOrEmpty
    }

    It 'permits the exact containment PATCH' {
        $permit = & $script:Module { Get-TripwireWritePermit -Method 'PATCH' -Path '/v1.0/users/abc' -Body @{ accountEnabled = $false } }
        $permit | Should -Not -BeNullOrEmpty
        $permit.Purpose | Should -Match 'disable'
    }

    It 'refuses every privilege-granting write, whatever it is called' {
        $forbidden = @(
            @{ M = 'POST'; P = '/v1.0/directoryRoles/x/members/$ref' }
            @{ M = 'POST'; P = '/v1.0/servicePrincipals/x/appRoleAssignments' }
            @{ M = 'POST'; P = '/v1.0/oauth2PermissionGrants' }
            @{ M = 'POST'; P = '/v1.0/groups/x/members/$ref' }
            @{ M = 'POST'; P = '/v1.0/users/x/authentication/methods' }
            @{ M = 'PATCH'; P = '/v1.0/policies/authorizationPolicy' }
            @{ M = 'DELETE'; P = '/v1.0/groups/x' }
            @{ M = 'POST'; P = '/v1.0/applications/x/addKey' }
        )
        foreach ($f in $forbidden) {
            $permit = & $script:Module { param($m, $p) Get-TripwireWritePermit -Method $m -Path $p -Body $null } $f.M $f.P
            $permit | Should -BeNullOrEmpty -Because "$($f.M) $($f.P) must never be permitted"
        }
    }

    It 'throws rather than issuing a write that is not on the allowlist' {
        Install-GraphStub -Module $script:Module
        { & $script:Module { Invoke-TripwireGraphWrite -Method 'POST' -Path '/v1.0/directoryRoles/x/members/$ref' } } |
            Should -Throw -ExpectedMessage '*refused a write*'
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0 -Because 'nothing should have reached Graph'
    }
}

Describe 'Decoy lifecycle safety' {

    BeforeEach {
        $script:Inventory = Join-Path ([System.IO.Path]::GetTempPath()) ("decoys-{0}.json" -f [Guid]::NewGuid())
        Install-GraphStub -Module $script:Module
        Clear-GraphStubCall -Module $script:Module
    }
    AfterEach {
        Remove-Item -LiteralPath $script:Inventory -ErrorAction SilentlyContinue
    }

    It 'plants a decoy user without granting it a group, a role, a licence or a permission' {
        New-TripwireDecoy -Type User -DisplayName 'svc-bait' -UserPrincipalName 'svc-bait@contoso.com' `
            -Path $script:Inventory -Confirm:$false | Out-Null

        $calls = Get-GraphStubCall -Module $script:Module
        @($calls).Count | Should -Be 1
        $calls[0].Method | Should -Be 'POST'
        $calls[0].Uri | Should -Be '/v1.0/users'
        $calls[0].Body | Should -Not -Match 'appRoleAssignment|memberOf|assignedLicenses|directoryRole'
    }

    It 'never writes the decoy password to the inventory or returns it to the caller' {
        $decoy = New-TripwireDecoy -Type User -DisplayName 'svc-bait' -UserPrincipalName 'svc-bait@contoso.com' `
            -Path $script:Inventory -Confirm:$false
        ($decoy | ConvertTo-Json -Depth 6) | Should -Not -Match 'password'
        (Get-Content -LiteralPath $script:Inventory -Raw) | Should -Not -Match 'password'
    }

    It 'writes nothing at all under -WhatIf' {
        New-TripwireDecoy -Type User -DisplayName 'svc-bait' -UserPrincipalName 'svc-bait@contoso.com' `
            -Path $script:Inventory -WhatIf | Out-Null
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
        Test-Path -LiteralPath $script:Inventory | Should -BeFalse
    }

    It 'registers an existing object as a decoy without touching the tenant' {
        New-TripwireDecoy -Type User -DisplayName 'p.morales' -ObjectId 'u-old-1' -RegisterOnly `
            -Path $script:Inventory -Confirm:$false | Out-Null
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
        @(Get-TripwireDecoy -Path $script:Inventory).Count | Should -Be 1
    }

    It 'REFUSES to delete anything that is not in its own inventory' {
        New-TripwireDecoy -Type User -DisplayName 'svc-bait' -ObjectId 'obj-1' -RegisterOnly `
            -Path $script:Inventory -Confirm:$false | Out-Null
        Clear-GraphStubCall -Module $script:Module

        { Remove-TripwireDecoy -Id 'decoy-not-mine' -Path $script:Inventory -Confirm:$false } |
            Should -Throw -ExpectedMessage '*not in the decoy inventory*'
        @(Get-GraphStubCall -Module $script:Module).Count | Should -Be 0
    }

    It 'deletes only the decoy object it recorded' {
        $d = New-TripwireDecoy -Type User -DisplayName 'svc-bait' -ObjectId 'obj-1' -RegisterOnly `
            -Path $script:Inventory -Confirm:$false
        Clear-GraphStubCall -Module $script:Module

        Remove-TripwireDecoy -Id $d.id -Path $script:Inventory -Confirm:$false | Out-Null
        $calls = Get-GraphStubCall -Module $script:Module
        @($calls).Count | Should -Be 1
        $calls[0].Method | Should -Be 'DELETE'
        $calls[0].Uri | Should -Be '/v1.0/users/obj-1'
        @(Get-TripwireDecoy -Path $script:Inventory).Count | Should -Be 0
    }
}

Describe 'Blind runs announce themselves' {

    It 'warns instead of returning quietly when the decoy inventory is empty' {
        $warnings = @()
        Watch-TripwireActivity -Decoy @() -Baseline (New-TestBaseline) -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
        ($warnings -join ' ') | Should -Match 'blind run'
    }

    It 'warns instead of returning quietly when there is no baseline file' {
        $missing = Join-Path ([System.IO.Path]::GetTempPath()) ("nope-{0}.json" -f [Guid]::NewGuid())
        $warnings = @()
        Get-TripwireBaseline -Path $missing -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
        ($warnings -join ' ') | Should -Match 'WITHHELD'
    }

    It 'refuses to continue on a corrupt state file rather than treating it as empty' {
        $bad = Join-Path ([System.IO.Path]::GetTempPath()) ("bad-{0}.json" -f [Guid]::NewGuid())
        Set-Content -LiteralPath $bad -Value '{ this is not json'
        { Get-TripwireDecoy -Path $bad } | Should -Throw -ExpectedMessage '*not valid JSON*'
        Remove-Item -LiteralPath $bad -ErrorAction SilentlyContinue
    }
}
