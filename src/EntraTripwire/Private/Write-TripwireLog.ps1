<#
.SYNOPSIS
    Structured internal logging.

.DESCRIPTION
    Detection tooling has one logging rule that matters: never write a message on a
    channel the caller cannot see and then treat it as if the caller was told. Warnings
    go to the warning stream (visible by default), everything else to verbose. Nothing
    here writes to the host, so output redirection and CI capture behave predictably.
#>
function Write-TripwireLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Message,

        [ValidateSet('Info', 'Warn', 'Debug')]
        [string] $Level = 'Info'
    )

    $stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "[$stamp] [EntraTripwire] $Message"

    switch ($Level) {
        'Warn' { Write-Warning $line }
        'Debug' { Write-Debug $line }
        default { Write-Verbose $line }
    }
}
