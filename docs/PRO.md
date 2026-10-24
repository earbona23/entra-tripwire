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

Email **earbona@arrankago.com** with the name to put on the licence. You get the key by
return email, usually the same day. That is the whole process: there is no account to
create and nothing to install.

Sponsoring at or above the monthly price on
**[GitHub Sponsors](https://github.com/sponsors/earbona23)** also covers it — custom
amounts are accepted there. Email after sponsoring so the key can be issued to the right
organisation name.

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
## Pricing

Per organisation, unlimited seats. The licence is a signed file, verified offline — no
account, no phone-home.

| | Monthly | Annual (two months free) |
|---|:--:|:--:|
| This tool, Pro | US$29 | US$290 |
| Both tools (revtriage · EntraTripwire) | US$69 | US$690 |

containment-cut is listed as a third tool elsewhere, but its Pro features are not
implemented yet, so it is **not part of this bundle and not on sale** — see
[its Pro page](https://github.com/earbona23/containment-cut/blob/main/docs/pro.md).

To buy, email **earbona@arrankago.com** with the name to put on the licence. You get the
key by return email, usually the same day.
