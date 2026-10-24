<#
    Normalisation of the two Graph log shapes into one 'touch' record.

    A TOUCH is an observed contact with a decoy. A TRIP is a touch that has been scored.
    Keeping the words apart keeps the pipeline honest: collection produces touches and
    cannot produce a verdict, scoring produces trips and cannot produce evidence.

    Timestamps are resolved with ConvertTo-TripwireUtcOrNull rather than the throwing
    variant. A record Graph returned without a usable date is still a contact with a decoy
    and is still worth reporting; what it is not worth is abandoning every other record in
    the batch, which is what a terminating parse error here used to do. A touch with a
    $null timestamp is never correlated and the signals that need a clock withhold
    themselves, so it arrives in front of the operator marked degraded instead of absent.
#>

<#
.SYNOPSIS
    Index the decoy inventory by every identifier a log might refer to it by.
#>
function Get-TripwireDecoyIndex {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Decoy)

    $index = @{}
    foreach ($d in $Decoy) {
        foreach ($key in @($d.objectId, $d.appId, $d.upn, $d.displayName)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$key)) {
                $index[([string]$key).ToLowerInvariant()] = $d
            }
        }
    }
    return $index
}

<#
.SYNOPSIS
    Convert a Graph sign-in log record into a touch, or $null if no decoy is involved.
.DESCRIPTION
    A sign-in record matches when the principal that signed in IS a decoy -- somebody is
    using credentials that were planted to be found. That is the highest-value observation
    the tool makes, and it is why decoy secrets are worth planting at all.
#>
function ConvertTo-TripwireTouchFromSignIn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] [hashtable] $DecoyIndex
    )

    $decoy = $null
    foreach ($candidate in @($Record.userId, $Record.userPrincipalName, $Record.appId)) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate)) { continue }
        $hit = $DecoyIndex[([string]$candidate).ToLowerInvariant()]
        if ($null -ne $hit) { $decoy = $hit; break }
    }
    if ($null -eq $decoy) { return $null }

    $errorCode = 0
    if ($null -ne $Record.status -and $null -ne $Record.status.errorCode) { $errorCode = [int]$Record.status.errorCode }

    $lat = $null; $lon = $null; $country = $null
    if ($null -ne $Record.location) {
        $country = [string]$Record.location.countryOrRegion
        if ($null -ne $Record.location.geoCoordinates) {
            $lat = $Record.location.geoCoordinates.latitude
            $lon = $Record.location.geoCoordinates.longitude
        }
    }

    [pscustomobject]@{
        id        = [string]$Record.id
        timestamp = ConvertTo-TripwireUtcOrNull $Record.createdDateTime
        decoyId   = [string]$decoy.id
        source    = 'SignInLog'
        operation = "Sign-in to $($Record.appDisplayName)"
        result    = if ($errorCode -eq 0) { 'success' } else { "failure ($errorCode)" }
        actor     = [pscustomobject]@{
            id          = [string]$Record.userId
            upn         = [string]$Record.userPrincipalName
            displayName = [string]$Record.userDisplayName
            type        = 'DecoyPrincipal'
        }
        ip        = [string]$Record.ipAddress
        country   = $country
        asn       = [string]$Record.autonomousSystemNumber
        latitude  = $lat
        longitude = $lon
    }
}

<#
.SYNOPSIS
    Convert a Graph directory-audit record into a touch, or $null if no decoy is involved.
.DESCRIPTION
    An audit record matches when a decoy appears in targetResources -- somebody READ, listed
    or modified the decoy object. Reading is the interesting case: enumeration precedes use.
#>
function ConvertTo-TripwireTouchFromAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] [hashtable] $DecoyIndex
    )

    $decoy = $null
    foreach ($target in @($Record.targetResources)) {
        if ($null -eq $target) { continue }
        foreach ($candidate in @($target.id, $target.userPrincipalName, $target.displayName)) {
            if ([string]::IsNullOrWhiteSpace([string]$candidate)) { continue }
            $hit = $DecoyIndex[([string]$candidate).ToLowerInvariant()]
            if ($null -ne $hit) { $decoy = $hit; break }
        }
        if ($null -ne $decoy) { break }
    }
    if ($null -eq $decoy) { return $null }

    $actorId = ''; $actorUpn = ''; $actorName = ''; $actorType = 'Unknown'; $ip = ''
    if ($null -ne $Record.initiatedBy) {
        if ($null -ne $Record.initiatedBy.user) {
            $actorId = [string]$Record.initiatedBy.user.id
            $actorUpn = [string]$Record.initiatedBy.user.userPrincipalName
            $actorName = $actorUpn
            $actorType = 'User'
            $ip = [string]$Record.initiatedBy.user.ipAddress
        }
        elseif ($null -ne $Record.initiatedBy.app) {
            $actorId = [string]$Record.initiatedBy.app.servicePrincipalId
            $actorName = [string]$Record.initiatedBy.app.displayName
            $actorType = 'ServicePrincipal'
        }
    }

    [pscustomobject]@{
        id        = [string]$Record.id
        timestamp = ConvertTo-TripwireUtcOrNull $Record.activityDateTime
        decoyId   = [string]$decoy.id
        source    = 'DirectoryAudit'
        operation = [string]$Record.activityDisplayName
        result    = [string]$Record.result
        actor     = [pscustomobject]@{
            id          = $actorId
            upn         = $actorUpn
            displayName = $actorName
            type        = $actorType
        }
        # Directory audits carry no geo enrichment. The origin signal will withhold the
        # country and ASN components rather than score an absent country as "unseen",
        # which would make every audit-sourced touch look like it came from nowhere.
        ip        = $ip
        country   = $null
        asn       = $null
        latitude  = $null
        longitude = $null
    }
}
