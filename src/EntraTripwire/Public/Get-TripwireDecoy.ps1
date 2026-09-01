<#
.SYNOPSIS
    Read the local decoy inventory.

.DESCRIPTION
    The inventory is the tool's ground truth about what is bait and what is furniture, and
    it lives on the operator's machine rather than in the directory. Marking decoys with a
    directory attribute would hand the answer to exactly the enumerator the decoys exist to
    catch: anyone who can list users can then filter them out.

.PARAMETER Demo
    Read the synthetic inventory that ships inside the module. No tenant, no local state.

.PARAMETER Path
    Read a specific inventory file instead of the profile default.

.PARAMETER Id
    Return only the decoy with this id.

.EXAMPLE
    Get-TripwireDecoy -Demo | Format-Table id, type, displayName, legitimateUseCount
#>
function Get-TripwireDecoy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [switch] $Demo,
        [string] $Path,
        [string] $Id
    )

    if (-not $Path) {
        $Path = if ($Demo) { Get-TripwireDemoPath -Name 'decoys.json' } else { Get-TripwireStatePath -Name 'decoys.json' }
    }

    $data = Read-TripwireJsonFile -Path $Path
    $decoys = if ($null -eq $data) { @() } elseif ($null -ne $data.decoys) { @($data.decoys) } else { @($data) }

    # Emitted one per pipeline object, the standard contract for a Get-* command, so a
    # caller writing @(Get-TripwireDecoy) gets the decoys rather than a one-element array
    # containing all of them. Returning ,@($x) here would do exactly that, and the symptom
    # is silent: the inventory looks like a single unmatchable object and every touch stops
    # being detected.
    if ($Id) { return $decoys | Where-Object { [string]$_.id -eq $Id } }
    return $decoys
}
