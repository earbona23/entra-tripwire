# EntraTripwire Pro

Everything that **detects** is free and MIT-licensed. Pro unlocks the parts that **act** or
**scale**.

## Free vs Pro

| | Free (MIT) | Pro |
|---|:--:|:--:|
| Plant decoy users, applications and secrets | yes | yes |
| Watch sign-in and directory audit logs | yes | yes |
| The whole confidence engine — four signals, suppression, bands, degraded flag | yes | yes |
| Tenant baseline, impossible travel, cross-decoy correlation | yes | yes |
| DEMO mode against the shipped fixtures | yes | yes |
| Self-contained HTML report and JSON export | yes | yes |
| Containment **plan** — every action with the exact Graph call, ready to run by hand | yes | yes |
| Containment **execution** — revoke sessions, disable the used decoy, capture context | — | yes |
| SOAR / SIEM delivery — JSONL export and webhook dispatch | — | yes |
| Multiple tenant profiles in one installation | — | yes |

Nothing the module *detects* is behind the licence. A free installation sees exactly what a
Pro installation sees, scores it identically, and is handed the complete remediation plan —
it just does not press the button for you.

## How the entitlement works

Pro is a separate module, `EntraTripwirePro`, and **holding it is the entitlement**. Install it
and Pro is on; there is nothing to activate, no account, no activation server, no telemetry and
no callback. A detection tool that phones home during an incident is a detection tool that leaks
the incident.

```powershell
Get-TripwireLicense       # installed? which capabilities? and if not, why not
```

That design is the honest version of a paid feature in an MIT project. A licence check inside
MIT-licensed code is a line anyone may delete, and deleting it would uncover working capability
underneath. The three paid capabilities are not in the free repository at all, so there is nothing
to uncover: a fork has to write them, not remove a check.

What stays in the free module on purpose, and what you can therefore audit yourself:

| In this repository, and readable | Why it matters to you |
|---|---|
| Every verdict: detection, scoring, suppression, the plan | No paid code can change what your tenant is told about itself |
| The Graph write allowlist | The paid module writes **through** it, so it cannot issue a call the free module forbids |
| `ShouldProcess` and the audit log | The confirmation you answer, and the record of what happened, are in the module you can read |

### A licence key, when there is one

A key is only needed for a **time-limited or feature-scoped** licence, such as an evaluation. It
is an ECDSA P-256 token verified entirely offline against a public key embedded in the paid
module:

```powershell
Enable-TripwirePro -LicenseKey 'TRIPWIRE-xxxxx.yyyyy'
```

It can also be supplied as `$env:ENTRATRIPWIRE_LICENSE_KEY`, which is usually what you want in a
scheduled task or a container. The entitlement is re-verified on every call rather than cached at
import, so a licence that expires mid-session stops working in that session. And a licence that is
present but does not verify entitles **nothing** — present-and-broken is not the same as absent,
and a lapsed licence that keeps working is the failure direction that costs somebody money.

## Getting Pro

**[consulting.arrankago.com](https://consulting.arrankago.com)** — tiers and purchase. From
**$49 per organisation per month** for Solo, with the full matrix under [Pricing](#pricing) below.

Or email **earbona@arrankago.com** with the organisation name to put on the licence. You get the
module and, where the licence is time-limited, its key. One person issues these by hand, so
no turnaround is promised here; buying through the site is the faster path.

Managed security and M365/Entra identity assessments are on the same site if you would rather have
the work done than run the module yourself.

## What Pro containment actually does

Five gates, all of which must be open before a single write is issued: the trip must be in
the **High** band, it must not be **degraded**, `-Execute` must be passed, `ShouldProcess`
must confirm, and the `containment` feature must be licensed. See
[scoring.md](scoring.md#the-two-structural-invariants) and the module help for
`Invoke-TripwireContainment`.

At most it revokes the actor's refresh tokens, disables the decoy whose credential was used,
and writes an incident capture to disk. It never contacts, probes or responds to the source
of the intrusion — the write allowlist has no entry that could.
## Pricing

Per organisation, per month, in USD. Annual billing is two months free, so the yearly figure is
ten times the monthly one. Unlimited users within the seat band.

| | Solo (1) | Team (≤10) | Business (≤50) | Enterprise |
|---|:--:|:--:|:--:|:--:|
| **Monthly** | **$49** | **$149** | **$449** | contact |
| **Annual** | $490 | $1,490 | $4,490 | contact |

The **Suite (all tools)** plan is **$99** Solo, **$349** Team and **$999** Business per month,
which is the better deal if you use more than one of them. What that plan covers is listed on the
site, since which tools have a paid tier changes as they ship one.

**[Buy at consulting.arrankago.com](https://consulting.arrankago.com)**, or email
**earbona@arrankago.com** with the organisation name to put on the licence. Those figures are the
ones on that site; if you ever see the two disagree, the site is right and this page is stale.

The licence itself is a signed file verified offline: no account, no activation server, no
phone-home.
