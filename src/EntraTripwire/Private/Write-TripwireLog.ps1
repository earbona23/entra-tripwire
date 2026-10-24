<#
.SYNOPSIS
    Structured internal logging, and the narration the guided run reads out.

.DESCRIPTION
    Detection tooling has one logging rule that matters: never write a message on a
    channel the caller cannot see and then treat it as if the caller was told. Warnings
    go to the warning stream (visible by default), everything else to verbose. Nothing
    here writes to the host, so output redirection and CI capture behave predictably.

    Write-TripwireNotice is the operator-facing half of the same rule. A guided run has to
    say what it is doing while it does it, and the obvious way to do that -- Write-Host --
    writes to a stream nothing can capture, redirect or silence. Narration goes to the
    INFORMATION stream instead: visible by default inside Start-EntraTripwire, silenced
    with -InformationAction SilentlyContinue, and captured by -InformationVariable, which
    is also how the tests assert on what the operator was told.
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

<#
.SYNOPSIS
    The ANSI escapes the narration uses, or empty strings when colour is not wanted.

.DESCRIPTION
    Colour is decoration, never information: every line this module writes says what it
    means in words, so a terminal that strips the escapes loses nothing. The palette is
    deliberately narrow -- bold for structure, one colour each for "needs attention",
    "act on this" and "paste this" -- because a report that colours everything has told
    the reader nothing about what to look at first.

    Three ways to turn it off, all honoured: NO_COLOR (the de facto convention),
    $PSStyle.OutputRendering set to PlainText, and a host too old to have $PSStyle.
#>
function Get-TripwirePalette {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $plain = @{ Head = ''; Good = ''; Warn = ''; Bad = ''; Dim = ''; Cmd = ''; Off = '' }

    if (-not [string]::IsNullOrEmpty($env:NO_COLOR)) { return $plain }

    # Wrapped because the whole feature is cosmetic. A host that answers any of this
    # unexpectedly must degrade to plain text, never fail the run that is reporting an
    # intrusion.
    try {
        if ($null -eq $PSStyle -or $PSStyle.OutputRendering -eq 'PlainText') { return $plain }
        return @{
            Head = [string]$PSStyle.Bold
            Good = [string]$PSStyle.Foreground.Green
            Warn = [string]$PSStyle.Foreground.Yellow
            Bad  = [string]$PSStyle.Foreground.Red
            Dim  = [string]$PSStyle.Foreground.BrightBlack
            Cmd  = [string]$PSStyle.Foreground.Cyan
            Off  = [string]$PSStyle.Reset
        }
    }
    catch { return $plain }
}

<#
.SYNOPSIS
    One line of operator-facing narration, on the information stream.

.PARAMETER Kind
    Heading   a section title
    Ok        a check that passed
    Neutral   a check that is neither pass nor problem, aligned with the markers above
    Attention something the operator should decide about
    Alert     something that needs action now
    Detail    supporting text, dimmed
    Command   a command to copy, indented and coloured as such
    Plain     no marker, no colour

.PARAMETER Indent
    Levels of two-space indentation.
#>
function Write-TripwireNotice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string] $Message,

        [ValidateSet('Plain', 'Heading', 'Ok', 'Neutral', 'Attention', 'Alert', 'Detail', 'Command')]
        [string] $Kind = 'Plain',

        [ValidateRange(0, 6)]
        [int] $Indent = 0
    )

    $p = Get-TripwirePalette
    $pad = ' ' * (2 * $Indent)

    # ASCII markers on purpose. A Windows console still running a legacy code page renders
    # a tick or a cross as mojibake, and a status marker nobody can read is worse than a
    # plain one.
    $line = switch ($Kind) {
        'Heading' { "$($p.Head)$pad$Message$($p.Off)" }
        'Ok' { "$pad$($p.Good)[ ok ]$($p.Off) $Message" }
        'Neutral' { "$pad$($p.Dim)[ -- ]$($p.Off) $Message" }
        'Attention' { "$pad$($p.Warn)[ !  ]$($p.Off) $Message" }
        'Alert' { "$pad$($p.Bad)[ !! ]$($p.Off) $Message" }
        'Detail' { "$($p.Dim)$pad$Message$($p.Off)" }
        'Command' { "$pad$($p.Cmd)$Message$($p.Off)" }
        default { "$pad$Message" }
    }

    Write-Information -MessageData $line -Tags 'EntraTripwire'
}
