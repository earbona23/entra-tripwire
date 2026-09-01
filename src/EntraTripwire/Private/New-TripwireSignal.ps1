<#
.SYNOPSIS
    The shape of one scoring signal.

.DESCRIPTION
    Every signal carries three things the score alone cannot: whether it could be
    evaluated at all, the raw 0..1 strength, and a rationale in words. A signal that
    could not be evaluated is Available = $false and contributes ZERO -- it is never
    silently treated as "no anomaly", and it never causes the remaining weights to be
    renormalised upward. Renormalising would let a tenant with no baseline produce
    higher confidence than a tenant with one, which is the exact inversion a detector
    must not have.
#>
function New-TripwireSignal {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [double] $Weight,
        [double] $Raw = 0.0,
        [bool] $Available = $true,
        [string] $Rationale = ''
    )

    if ($Raw -lt 0) { $Raw = 0.0 }
    if ($Raw -gt 1) { $Raw = 1.0 }
    $effective = if ($Available) { $Raw } else { 0.0 }

    [pscustomobject]@{
        Name      = $Name
        Weight    = [Math]::Round($Weight, 4)
        Raw       = [Math]::Round($effective, 4)
        Weighted  = [Math]::Round($effective * $Weight, 4)
        Available = $Available
        Rationale = $Rationale
    }
}
