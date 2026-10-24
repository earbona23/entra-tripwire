# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/earbona23/entra-tripwire/security/advisories/new)
on this repository. Please do not open a public issue for anything that would let someone
misuse the write path or defeat detection.

If the advisory form is unavailable to you, email **earbona@arrankago.com** with
`entra-tripwire security` in the subject. Do not include tenant identifiers, real object
IDs or captured telemetry in a first message; a description of the mechanism is enough to
start.

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

## What is not a vulnerability here

- **Removing the licence check in your own fork.** The MIT Licence permits it and the code
  is published. It is a licensing and funding question, not a security one, and it is
  addressed in `LICENSING.md`. A bypass that *executes containment* is the exception above
  and is in scope.
- **Findings against a tenant you are not authorised to administer.** Do not test this
  module, or anything else, against someone else's directory. Reports arising from
  unauthorised access will not be acted on and will be treated as what they are.
- **The absence of a feature.** A missing detection is an issue, not an advisory. Missing
  detections that the module *claims* to perform are the "silent blindness" class above
  and do belong in an advisory.

## What to expect

One maintainer, no on-call rotation, and a stated target rather than a guarantee:

- acknowledgement within **5 days**;
- an assessment, with a severity and whether it is accepted, within **14 days**;
- a fix or a documented mitigation for an accepted report within **90 days**, sooner where
  the class is one of the first two above.

If a report is still unacknowledged after 14 days, treat the silence as a failure of this
process rather than a decision, and escalate by email to the address above.

Coordinated disclosure is requested: please hold public details, including a proof of
concept, until a fix ships or the 90 days elapse, whichever is first. Reporters are
credited in the advisory and in `CHANGELOG.md` by the name they ask for, or not at all if
they prefer. There is no bounty programme and there is no budget for one; saying so up
front is more useful than letting you find out at the end.

Acting in good faith under this policy, against your own tenant or the shipped fixtures,
is welcome and will not be met with a complaint from the maintainer. That is a statement
of intent by one person, not a legal safe harbour granted on behalf of anyone else, and it
cannot bind Microsoft or any tenant owner.

## Supported versions

The latest released version is the supported one. Fixes are issued against `main` and
released; there are no maintained back-release branches, and backports are not provided.

## Scope notes

The decoy inventory and the incident captures contain tenant data. They are written under the
user's configuration directory and are excluded from git; treat them as you would any other
security telemetry.

The licence signing key lives in `.secrets/`, which is in `.gitignore`. Only the verification
public key ships inside the module, and it can verify a signature but never mint one.
