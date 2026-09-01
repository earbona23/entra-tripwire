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

## How the licence works

An ECDSA P-256 token, verified **entirely offline** against a public key embedded in the
module. No account, no activation server, no telemetry, no callback. A detection tool that
phones home during an incident is a detection tool that leaks the incident.

```powershell
Enable-TripwirePro -LicenseKey 'TRIPWIRE-xxxxx.yyyyy'
Get-TripwireLicense
```

The key can also be supplied as `$env:ENTRATRIPWIRE_LICENSE_KEY`, which is usually what you
want in a scheduled task or a container.

The entitlement is re-verified from the key on every call rather than cached at import, so a
licence that expires mid-session stops working in that session.

## Getting a licence

- **[GitHub Sponsors](https://github.com/sponsors/earbona23)** — sponsoring at the Pro tier
  includes a key.
- **[Patreon](https://www.patreon.com/EduardArbona)** — same.
- Checkout through Polar / Lemon Squeezy is being set up; until it is live, sponsorship is
  the route.

Keys are per-organisation and perpetual unless a term is stated on the key itself.

## What Pro containment actually does

Five gates, all of which must be open before a single write is issued: the trip must be in
the **High** band, it must not be **degraded**, `-Execute` must be passed, `ShouldProcess`
must confirm, and the `containment` feature must be licensed. See
[scoring.md](scoring.md#the-two-structural-invariants) and the module help for
`Invoke-TripwireContainment`.

At most it revokes the actor's refresh tokens, disables the decoy whose credential was used,
and writes an incident capture to disk. It never contacts, probes or responds to the source
of the intrusion — the write allowlist has no entry that could.
