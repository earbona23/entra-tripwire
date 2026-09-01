# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

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
