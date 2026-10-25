# Contributing

Bug reports, corrections to the calibration, and new suppression rules are all welcome.

Before a large change, open an issue. A refactor nobody asked for is expensive to review
and usually ends up declined, which wastes your weekend rather than the maintainer's.
`GOVERNANCE.md` lists what gets merged readily and what is permanently out of scope, and
it is short on purpose.

## Licensing of what you send

Two things, once each, and then you can forget about them.

**1. Sign off every commit.** Every commit must carry a `Signed-off-by` line certifying
the [Developer Certificate of Origin](DCO): that you wrote the patch, or otherwise have
the right to submit it under the project's licence.

```bash
git commit -s -m "fix: the thing"
git config --global user.name  "Your Name"      # the sign-off uses these,
git config --global user.email "you@example.com" # so set them once
```

Forgot on the last commit: `git commit --amend -s --no-edit`. Forgot across a branch:
`git rebase --signoff main`. Then force-push the branch.

**2. Accept the Contributor Licence Agreement, once.** A bot comments on your first pull
request with a one-click link. It takes a few seconds and it covers your future
contributions too.

[`CLA.md`](CLA.md) says what it does in its own first paragraphs, so this is only the
summary: **you keep the copyright in your contribution**, and you grant the maintainer a
licence broad enough to relicense the project and to use your contribution in the paid
edition. The project has one author and a commercial edition, and without that grant it
could never change its own licence again. If that trade is not one you want to make, an
issue with a reproduction or a failing test case is covered by none of it and is still one
of the most useful things anyone sends.

## Before you open a pull request

```powershell
Install-Module Pester, PSScriptAnalyzer -Scope CurrentUser

Invoke-Pester ./tests -Output Detailed
Invoke-ScriptAnalyzer -Path ./src -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
pwsh ./scripts/mutation-test.ps1
```

All three must be clean. CI runs the same on ubuntu and windows.

If you are working from a fork, your first CI run waits for manual approval and does not
receive repository secrets. That is a standing setting on this repository and not a
comment on your pull request.

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

## Third-party code

If any part of what you send is not yours, say so in the pull request: where it came from,
under what licence, and what it is. Compatible code is usually fine with attribution;
code of unknown provenance never is, and finding out after a merge is much worse than
finding out before one. This is also what you are certifying in clause (b) of the DCO.

## Security

Do not open an issue or a pull request for a vulnerability. `SECURITY.md` asks for a
private advisory, and tells you which classes of bug this project treats as security
rather than usability. "The module reported clean about something it never looked at" is
on that list.

## Releasing

Only a tag publishes, and only through `.github/workflows/publish.yml`. Nothing is published
from a workstation: a `Publish-Module` run from a directory puts whatever happened to be in
that directory on the Gallery, and leaves no way to say which commit a published version
came from.

To cut a release:

1. Set `ModuleVersion` in `src/EntraTripwire/EntraTripwire.psd1`.
2. Close the `[Unreleased]` section of `CHANGELOG.md` as `## [x.y.z] - YYYY-MM-DD`.
3. Commit, then `git tag -a vx.y.z -m "EntraTripwire x.y.z"` and push the tag.

The workflow runs the whole of CI against the tagged tree — it calls `ci.yml` rather than
repeating it, so the release gate cannot come to check less than `main` does — and refuses to
publish unless the tag matches `ModuleVersion`, the CHANGELOG has a section for that version,
and the Gallery does not already have it. After publishing it waits until the Gallery
actually serves the version, because `Publish-Module` returning without an error is not proof
that anything was published.

A published version cannot be replaced, only superseded. If a release is wrong, the fix is
the next version.

The workflow reads the Gallery key from a repository secret named `PSGALLERY_API_KEY`, and
declares a `psgallery` environment so that a required reviewer can be added in the repository
settings to gate the publish step without changing this file.

## Credit

Your authorship is in the commit history, which is public and permanent. Substantial
contributions are also credited in `NOTICE` and in the release notes.
