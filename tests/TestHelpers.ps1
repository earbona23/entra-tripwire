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
