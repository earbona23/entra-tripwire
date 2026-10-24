# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `docs/distribution.md` — how this module is installed and run, measured against the
  alternatives. It answers whether a standalone `.exe` is worth shipping (it is not: a
  signature does not remove the SmartScreen warning, and Microsoft states that EV no longer
  bypasses it), establishes that a PowerShell module **cannot** be published to WinGet at
  all, and records what the paid boundary does and does not protect.

### Changed

- **The test and mutation counts in this file and in the README were stale.** The suite is
  **152 tests across eight files**, and the mutation harness runs **31 mutants, 31 killed,
  0 survived, 0 not applied**. The README badge still read `17/17` from the 1.0.0 release.
- Manifest metadata, for discoverability on the PowerShell Gallery: the `Description` now
  leads with the problem rather than the architecture and states that
  `Microsoft.Graph.Authentication` is needed only to connect a real tenant, which the
  Gallery's empty "Dependencies" section cannot convey on its own; `ReleaseNotes` carries
  the notes themselves instead of a bare link, because the Gallery renders that field as
  text; and the `Windows` and `Linux` platform tags were added, since both are proven by CI
  on every push. macOS is not tested and so is not tagged. No exported command changed.
- The README now states what an operator ends up with — the self-contained HTML report —
  and lists the Graph scopes with the reason for each one inline, rather than only linking
  to them. It also documents the two things the install actually requires of a first-time
  user: the PowerShell Gallery's untrusted-repository prompt, whose default answer is `N`,
  and `Update-Module` as the update path, since the Gallery has no way to notify an
  installed user that a new version exists.
- Statements about what any licence covers now live only in `LICENSING.md`. `SPONSORS.md`
  made such a statement and no longer does: it is a thanks page, not terms.

- **The paid capabilities moved out of this repository.** Containment execution, SOAR/SIEM
  delivery and per-tenant profile isolation are now a separate module, `EntraTripwirePro`,
  and holding it is the entitlement. The reason is stated plainly in `LICENSING.md`: a
  licence check inside MIT-licensed code is a line anyone may delete, and deleting this one
  would have uncovered working capability underneath. There is nothing here to uncover now.
- All fourteen commands are still exported, so nothing installed from the PowerShell
  Gallery breaks. `Get-TripwireLicense` reports which capabilities the paid module provides,
  and keeps every property it returned before. `Enable-TripwirePro` hands a key to that
  module, which verifies it, rather than storing a key it can no longer check.
- `Invoke-TripwireContainment` builds and prints the plan exactly as before, and now hands
  the confirmed steps to the paid module along with this module's allowlisted write
  gateway, so a paid build still cannot issue a Graph call this module does not permit.
- Named tenant profiles now isolate state per profile instead of only being gated. The
  default profile resolves where it always did.

### Removed

- `src/EntraTripwire/Private/License.ps1` and `Private/Send-TripwireWebhook.ps1`. **This
  module now makes no outbound call other than Microsoft Graph**, which is a stronger
  property than the one the README used to claim, and there is a test for it.

### Fixed

- A scoring policy handed an incomplete `-Override` is refused with the member named,
  instead of leaving a threshold `$null` — where `50 -ge $null` is `$true` in PowerShell and
  banded seven of the nine shipped fixtures as High, the only band containment acts on.
- A record with no usable timestamp no longer aborts the whole analysis, and withholds the
  signals it cannot support instead of scoring them.
- Four licence paths that failed open or crashed: a malformed expiry, an empty feature list,
  a signed payload that is not a licence object, and an unreadable licence file.
- Containment targets the decoy recorded in the local inventory rather than the principal
  named in a log record.
- Correlation is roughly linear rather than quadratic: 9.9 s to 1.9 s over 2,000 touches,
  with output verified byte-identical over 1,203 randomised cases.

## [1.0.0] - 2026-09-01

First release.

### Added

- **Decoy planting.** `New-TripwireDecoy` creates decoy users and application registrations,
  optionally with a client secret on an application that holds no API permissions.
  `-RegisterOnly` records an existing object as a decoy without touching the tenant.
  `Remove-TripwireDecoy` refuses any object that is not in the local inventory.
- **Detection.** `Watch-TripwireActivity` reads Entra sign-in logs and directory audit logs,
  normalises both into decoy touches, correlates them per actor, and returns scored trips.
- **The confidence engine.** `Measure-TripwireConfidence` scores a touch with four weighted
  signals — decoy purity (0.40), origin anomaly (0.25), cross-decoy fan-out (0.25) and
  off-hours (0.10) — after two hard suppression rules. `Invoke-TripwireAnalysis` correlates
  and scores a whole set. `Get-TripwirePolicy` exposes the calibration as data.
- **Withheld signals.** A signal that cannot be evaluated contributes zero and the weights
  are not renormalised; the trip is flagged `Degraded` and names what was withheld.
- **Tenant baseline.** `Get-TripwireBaseline -Build` derives countries, autonomous systems, a
  24-hour histogram and per-actor last known positions from the tenant's own sign-in history.
- **Containment.** `Invoke-TripwireContainment` returns a complete plan for free and, with a
  Pro licence and four other gates open, executes it: revoke the actor's sessions, disable the
  used decoy, capture the context to disk.
- **Reporting.** `Export-TripwireReport` writes a self-contained HTML report (free), JSON
  (free), or JSONL and webhook delivery (Pro).
- **DEMO mode.** Every command that reads runs against synthetic fixtures shipped inside the
  module, with no tenant, no credentials, no network and no dependency installed.
- **Offline Pro licensing.** ECDSA P-256, verified locally. `Enable-TripwirePro`,
  `Get-TripwireLicense`.
- **119 tests** across seven files, and a mutation harness (`scripts/mutation-test.ps1`) that
  reports Killed / SURVIVED / NOT APPLIED. 17 mutants, 17 killed.
- **CI** on ubuntu and windows: manifest validation, a dependency-free DEMO run, lint, tests,
  and the mutation job.
