<!--
Thanks for this. Four short sections; delete whatever does not apply.
Before a large change, an issue first saves you the most time. See GOVERNANCE.md.
-->

## What this changes, and why

<!-- The "why" is the part a reviewer cannot reconstruct from the diff. -->

## How it was verified

<!-- Paste the result, not just a claim that it is green. -->

- [ ] `Invoke-Pester ./tests -Output Detailed` is clean
- [ ] `Invoke-ScriptAnalyzer -Path ./src -Recurse -Settings ./PSScriptAnalyzerSettings.psd1` is clean
- [ ] `pwsh ./scripts/mutation-test.ps1` is clean
- [ ] New behaviour has a mutant in `scripts/mutation-test.ps1` and the harness reports `Killed`

## Sensitive surfaces

Tick only what this pull request actually touches, and answer the question next to it.

- [ ] **Write allowlist** (`Invoke-TripwireGraphWrite`) — justify the new entry, and say
      what changed in `tests/Safety.Tests.ps1` and why it was deliberate.
- [ ] **Calibration** (`Get-TripwirePolicy`, signal weights) — what happens to the two
      invariants: no single signal reaches High alone, and a contaminated decoy never
      reaches High?
- [ ] **Licence gate** (`License.ps1`, `Enable-TripwirePro`) — see `LICENSING.md` first.
- [ ] **A new dependency** — the module must import and run DEMO with nothing installed.
      Argue against that promise.
- [ ] None of the above.

## Licensing

- [ ] Every commit is signed off (`git commit -s`), certifying the [DCO](../DCO).
- [ ] I have accepted the [Contributor Licence Agreement](../CLA.md) (the bot links it on
      your first pull request; once per person, not once per pull request).
- [ ] Any third-party code is identified above, with its source and its licence.

<!--
From a fork, the first CI run waits for manual approval and gets no secrets.
That is a repository setting, not a comment on you.
-->
