# Contributing

Bug reports, corrections to the calibration, and new suppression rules are all welcome.

## Before you open a pull request

```powershell
Install-Module Pester, PSScriptAnalyzer -Scope CurrentUser

Invoke-Pester ./tests -Output Detailed
Invoke-ScriptAnalyzer -Path ./src -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
pwsh ./scripts/mutation-test.ps1
```

All three must be clean. CI runs the same on ubuntu and windows.

## The rules this codebase is built around

**A new test does not count until it has been killed by mutation.** If you add behaviour, add
a mutant to `scripts/mutation-test.ps1` that breaks it and confirm the harness reports
`Killed`. A test that passes with and without the defect is documentation, not a test.

**Absence of evidence is a third state.** If a signal, a check or a query cannot be evaluated,
it must say so — `Available = $false`, a warning, a thrown error — never a neutral value that
reads as "evaluated, found nothing". Most of the design in this module exists to keep that
distinction alive.

**The write surface is a negotiation, not a detail.** Anything that needs a new entry in
`Invoke-TripwireGraphWrite`'s allowlist has to justify it in the pull request, and
`tests/Safety.Tests.ps1` has to be updated deliberately rather than incidentally.

**Nothing offensive.** Deception is defensive. Contacting, probing, scanning or feeding the
source of an intrusion is out of scope permanently, not pending a design.

**Source stays ASCII.** `src/` is linted with `PSUseBOMForUnicodeEncodedFile` enabled, so use
`--` rather than an em dash. Markdown is not linted and can use whatever reads best.

## Changing the calibration

The weights and thresholds in `Get-TripwirePolicy` are not arbitrary, and two invariants are
consequences of them rather than separate rules:

- no single signal can reach the High band alone;
- a contaminated decoy can never reach the High band.

If you propose different numbers, say in the pull request what happens to both invariants.
The tests will tell you if you broke them; the reasoning is what a reviewer needs.

## Style

- English identifiers, comments that explain *why* rather than *what*.
- Comment-based help on every public function, with at least one `.EXAMPLE`.
- New public functions go in `src/EntraTripwire/Public/` and are exported by the loader
  automatically; add them to `FunctionsToExport` in the manifest.
