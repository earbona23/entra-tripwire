<#
    Shared fixtures for the test suite. Dot-sourced from each file's BeforeAll.

    Everything here builds objects in memory. No test in this suite reaches a tenant, and
    the two that exercise the Graph gateways inject a recording stub into the module scope
    so the calls that WOULD have been made can be asserted on directly.
#>

function New-TestBaseline {
    param(
        [hashtable] $Countries = @{ US = 940; CA = 50; GB = 10 },
        [hashtable] $Asns = @{ '7922' = 900; '8075' = 100 },
        [int[]] $Hours,
        [hashtable] $ActorLastSeen = @{},
        [string[]] $SuppressedActors = @()
    )
    if (-not $Hours) {
        # A tenant that works office hours in UTC: peak 100 at 14:00, near-dead at 03:00.
        $Hours = @(2, 1, 1, 1, 1, 2, 5, 20, 60, 85, 95, 100, 98, 99, 100, 95, 80, 50, 25, 10, 6, 4, 3, 2)
    }
    [pscustomobject]@{
        generatedAt      = '2026-06-01T00:00:00Z'
        windowDays       = 30
        totalSignIns     = ($Hours | Measure-Object -Sum).Sum
        countries        = $Countries
        asns             = $Asns
        hourHistogram    = $Hours
        actorLastSeen    = $ActorLastSeen
        suppressedActors = $SuppressedActors
    }
}

function New-TestDecoy {
    param(
        [string] $Id = 'decoy-1',
        [string] $DisplayName = 'svc-decoy',
        [int] $LegitimateUseCount = 0,
        [string] $PlantedAt = '2026-01-01T00:00:00Z',
        [string] $PlantedBy = 'admin@contoso.com',
        [string] $ObjectId = 'obj-decoy-1',
        [string] $Type = 'User'
    )
    [pscustomobject]@{
        id                 = $Id
        type               = $Type
        objectId           = $ObjectId
        appId              = $null
        displayName        = $DisplayName
        upn                = "$DisplayName@contoso.com"
        plantedAt          = $PlantedAt
        plantedBy          = $PlantedBy
        legitimateUseCount = $LegitimateUseCount
        note               = ''
    }
}

function New-TestTouch {
    param(
        [string] $Id = 'touch-1',
        [string] $DecoyId = 'decoy-1',
        [string] $Timestamp = '2026-06-15T14:00:00Z',
        [string] $ActorId = 'actor-1',
        [string] $ActorUpn = 'intruder@contoso.com',
        [string] $Ip = '203.0.113.5',
        [AllowNull()] [string] $Country = 'US',
        [AllowNull()] [string] $Asn = '7922',
        $Latitude = $null,
        $Longitude = $null,
        [string] $Source = 'SignInLog',
        [string] $Operation = 'Sign-in'
    )
    [pscustomobject]@{
        id        = $Id
        timestamp = [DateTime]::Parse($Timestamp).ToUniversalTime()
        decoyId   = $DecoyId
        source    = $Source
        operation = $Operation
        result    = 'success'
        actor     = [pscustomobject]@{ id = $ActorId; upn = $ActorUpn; displayName = $ActorUpn; type = 'User' }
        ip        = $Ip
        country   = $Country
        asn       = $Asn
        latitude  = $Latitude
        longitude = $Longitude
    }
}

<#
    Install a recording stub for Invoke-MgGraphRequest inside the module scope.

    The test asserts on the exact calls the module WOULD issue, which is the property that
    matters for a tool with a write path.

    Note the dot-source rather than the call operator. `& $Module { function f {} }` runs in
    the module's scope but in a CHILD of it, so the definition evaporates when the block
    returns and the module keeps resolving the real command -- which, on a machine that
    happens to have Microsoft.Graph.Authentication installed, means the test tries to
    authenticate to a tenant. Dot-sourcing defines the stub in the module scope itself.
#>
function Install-GraphStub {
    param([Parameter(Mandatory)] $Module)
    . $Module {
        $script:TestGraphCalls = [System.Collections.Generic.List[object]]::new()
        # No [CmdletBinding()]: it would add a common -ErrorAction and collide with the
        # explicit one the gateway passes.
        function Invoke-MgGraphRequest {
            param(
                [string] $Method,
                [string] $Uri,
                $Body,
                $OutputType,
                $ErrorAction
            )
            $script:TestGraphCalls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body })
            return [pscustomobject]@{
                id         = 'created-object-id'
                appId      = 'created-app-id'
                secretText = 'decoy-secret-value'
            }
        }
    }
}

function Get-GraphStubCall {
    param([Parameter(Mandatory)] $Module)
    return @(& $Module { $script:TestGraphCalls })
}

function Clear-GraphStubCall {
    param([Parameter(Mandatory)] $Module)
    & $Module { $script:TestGraphCalls.Clear() }
}

<#
.SYNOPSIS
    Install a stand-in for EntraTripwirePro inside the module's session state.

.DESCRIPTION
    The paid capabilities live in a separate module, so a test that needs containment to
    execute has to provide one. This stub does exactly what the real module does -- it
    issues each confirmed step through the Writer the public module injects -- so every
    assertion about what did or did not reach Graph still holds, and the Graph stub sees
    the same calls it saw when the execution loop lived in this repository.

    Capabilities default to all three. Pass an empty array for an installed provider that
    entitles nothing, which is what a lapsed licence looks like.
#>
function Install-ProStub {
    param(
        [Parameter(Mandatory)] $Module,
        [string[]] $Capabilities = @('containment', 'soar', 'multitenant')
    )

    if (-not $script:RealProCapability) {
        $script:RealProCapability = & $Module { ${function:Invoke-TripwireProCapability} }
    }

    . $Module {
        param($caps)

        $script:TripwireProvider = [pscustomobject]@{
            Available    = (@($caps).Count -gt 0)
            Name         = 'EntraTripwirePro'
            Version      = [version]'1.0.0'
            Capabilities = @($caps)
            Reason       = if (@($caps).Count -gt 0) { $null } else { 'EntraTripwirePro is installed but reports no capabilities.' }
        }

        function script:Invoke-TripwireProCapability {
            param($Capability, [hashtable] $Arguments)

            if (-not $script:TripwireProvider.Available) { throw $script:TripwireProvider.Reason }

            switch ($Capability) {
                'Containment' {
                    $out = [System.Collections.Generic.List[object]]::new()
                    foreach ($s in $Arguments.Step) {
                        try {
                            switch ($s.Name) {
                                'CaptureContext' {
                                    if (-not (Test-Path -LiteralPath $Arguments.CapturePath)) {
                                        New-Item -ItemType Directory -Path $Arguments.CapturePath -Force | Out-Null
                                    }
                                    $Arguments.Trip | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $s.Path -Encoding utf8
                                }
                                'DisableDecoy' { & $Arguments.Writer -Method 'PATCH' -Path $s.Path -Body $s.Body | Out-Null }
                                default { & $Arguments.Writer -Method 'POST' -Path $s.Path | Out-Null }
                            }
                            $out.Add([pscustomobject]@{ Name = $s.Name; Status = 'Done'; Detail = $s.Path })
                        }
                        catch {
                            $out.Add([pscustomobject]@{ Name = $s.Name; Status = 'Failed'; Detail = $_.Exception.Message })
                        }
                    }
                    return $out.ToArray()
                }
                'Webhook' { return $null }
                'Profile' { return (Join-Path ([IO.Path]::GetTempPath()) "tripwire-profile-$($Arguments.ProfileName)") }
                'Activate' { return [pscustomobject]@{ Pro = $true; Features = @('containment', 'soar', 'multitenant') } }
            }
        }
    } $Capabilities
}

<#
.SYNOPSIS
    Remove the stand-in and pin the provider as absent.

.DESCRIPTION
    Pins it rather than clearing it on purpose. Clearing the cache would make the next
    lookup consult the machine, so these tests would change behaviour the day
    EntraTripwirePro is installed on the machine running them -- and the gate tests would
    stop testing the gate without anyone noticing.
#>
function Remove-ProStub {
    param([Parameter(Mandatory)] $Module)

    if ($script:RealProCapability) {
        . $Module { param($f) Set-Item -Path 'function:script:Invoke-TripwireProCapability' -Value $f } $script:RealProCapability
    }

    . $Module {
        $script:TripwireProvider = [pscustomobject]@{
            Available    = $false
            Name         = 'EntraTripwirePro'
            Version      = $null
            Capabilities = @()
            Reason       = 'EntraTripwirePro is not installed.'
        }
    }
}
