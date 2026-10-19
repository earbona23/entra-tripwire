# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/earbona23/entra-tripwire/security/advisories/new)
on this repository. Please do not open a public issue for anything that would let someone
misuse the write path or defeat detection.

If you cannot use the advisory form, email **earbona@arrankago.com** instead.

## What counts as a vulnerability here

This module is defensive tooling with a small but real write surface, so the interesting
classes are:

- **A write that escapes the allowlist.** Any input to `Invoke-TripwireGraphWrite` that
  results in a request outside the eight enumerated operations, or a PATCH body other than
  `{"accountEnabled": false}`.
- **Deletion of a non-decoy.** Any path by which `Remove-TripwireDecoy` deletes an object not
  in the local inventory.
- **Silent blindness.** Any condition under which the module reports a clean result while a
  signal, a query or a log page was not actually evaluated. A detector that says "nothing
  happened" about something it never looked at is a security defect in this project, not a
  usability one.
- **Injection into the report.** Any attacker-influenced string that reaches the rendered HTML
  unescaped.
- **Licence bypass** that also causes a tenant write — the gating itself is a commercial
  matter, but a bypass that executes containment is a safety matter.

## Scope notes

The decoy inventory and the incident captures contain tenant data. They are written under the
user's configuration directory and are excluded from git; treat them as you would any other
security telemetry.

The licence signing key lives in `.secrets/`, which is in `.gitignore`. Only the verification
public key ships inside the module, and it can verify a signature but never mint one.
