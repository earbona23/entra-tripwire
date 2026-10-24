# Governance

This project has one maintainer. Pretending otherwise with committees and a voting
procedure would be theatre, so this page describes what actually happens and where the
limits are.

## Who decides

**Eduard Arbona** is the author, copyright holder and sole maintainer. He decides what is
merged, what is released, how the calibration is set, and what the project is for. There
is no second person with write access, and the project does not claim a bus factor it does
not have.

Practical consequence for anyone considering depending on this: if the maintainer stops,
the project stops. The licence guarantees you can fork and continue; it guarantees nothing
about response times. That is the honest position for a single-maintainer tool and it is
better stated here than discovered during an incident.

## What gets merged

In rough order of how readily:

1. **Corrections that come with evidence.** A reproduction, a failing test, a Graph
   response that the parser mishandles. These are the most valuable thing anyone sends.
2. **New suppression rules and detection signals**, if they come with fixtures and a
   mutant. See `CONTRIBUTING.md`.
3. **Documentation that fixes something wrong**, including in the reasoning.
4. **Changes to the calibration**, if the pull request argues for the new numbers and says
   what happens to the two structural invariants.

What does not get merged, so that nobody writes it first:

- **Anything offensive.** Contacting, probing, scanning, or responding to the source of an
  intrusion is permanently out of scope. This is not a backlog item.
- **New entries in the write allowlist** without a written justification that survives
  review, and a deliberate update to `tests/Safety.Tests.ps1`.
- **Anything that makes an unevaluated signal look evaluated.** The third state is the
  design, not an inconvenience to be smoothed over.
- **Telemetry, analytics, activation servers or any network call home.** A detection tool
  that phones home during an incident leaks the incident.
- **Dependencies.** The module runs with nothing installed, and DEMO mode is a build gate
  that proves it. A pull request that adds a package has to argue against that promise.
- **Large unannounced rewrites.** Open an issue first. A refactor nobody asked for is
  expensive to review and usually ends up declined, which wastes your weekend, not the
  maintainer's.

## The paid edition and contributions

Three features read a licence entitlement: containment execution, SOAR/SIEM delivery and
multiple tenant profiles. Everything that detects is free and stays free.

If you contribute to a gated feature, your contribution is covered by `CLA.md` like any
other, which means it can end up in the commercial edition. That is said here in plain
sight rather than buried in a clause, because finding it out afterwards is the thing that
makes people angry, and reasonably so. If that is not a trade you want, contribute to the
free path or send an issue instead. Both are genuinely useful and neither is a lesser
contribution.

## Review

The maintainer reviews everything. There is no second reviewer, so the review leans on the
gates instead: CI on ubuntu and windows, PSScriptAnalyzer, Pester, and the mutation job
that introduces a real defect and fails if the suite stays green.

A pull request that touches the write surface, the licence gate or the scoring weights
gets read line by line and slowly. Expect questions rather than a quick merge. A
documentation fix usually goes in the same day.

Pull requests from forks do not get secrets and their first CI run needs manual approval.
That is a standing setting, not a comment on you.

## Releases

Releases are cut by the maintainer, tagged in git, and published from this repository.
Version numbers follow semantic versioning: the public function surface and the shape of
the objects they return are the contract. Changes to the scoring weights are documented in
`CHANGELOG.md` even when they do not change the function surface, because they change what
the tool tells you, which is the part you actually depend on.

The signing key for Pro licences is not in this repository and is not accessible to
contributors.

## Security reports

Not here. See `SECURITY.md`, which asks for a private advisory rather than an issue.

## Changing this document

The maintainer changes it. Suggestions in an issue are welcome and have been taken before.
