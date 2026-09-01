# Designing decoys that get found

A decoy that nobody takes is not a detector; it is an unused account. Everything below is
about making the bait plausible and keeping it inert.

## Make it look like it belongs

Name decoys the way your tenant names real things. Read your own directory first.

| Works | Does not work |
|---|---|
| `svc-backup-archive` | `DECOY_DO_NOT_USE` |
| `admin.legacy` | `honeypot01` |
| `sql-reporting-svc` | `zzz-test-account` |
| `Legacy VPN Connector` (application) | `Tripwire Bait App` |

The names an intruder is drawn to are the ones that suggest **privilege**, **age** or
**automation**: anything containing `admin`, `svc`, `legacy`, `backup`, `sync`, `sa_`,
`reporting`. Those are also the names that suggest nobody is watching.

## Seed the credential where it will be found, not where it will be used

The decoy user is created with a random password that is generated, sent to Graph, and
discarded. It is never returned and never stored, so nobody can sign in as it. The bait is
the *object*.

`-WithSecret` on an application decoy is the exception: it returns a client secret once, so
you can put it somewhere an intruder looks and a colleague does not.

- a decommissioned config file left in a repository
- a stale wiki or SharePoint page about a retired system
- a credential-manager entry on a jump host
- a comment in an old runbook

Because the decoy application holds **no API permissions**, the secret grants nothing. Its
only function is to be used, and be seen being used.

## Plant more than one

Fan-out is the strongest behavioural signal in the engine, and it needs at least two decoys
to exist at all. A single decoy can reach the Medium band; reaching High essentially requires
either an unmistakable origin anomaly or a sweep.

Spread them across the shapes an intruder enumerates: a couple of service accounts, a stale
administrator, an application registration with a secret. Four to eight is a reasonable
deployment for one tenant.

## Keep them pure, and be honest when they are not

The purity signal is the heaviest one, and it is only as good as the number you maintain. If
you discover something legitimate touching a decoy — a licensing script that enumerates every
user, an HR job that resolves display names — set `legitimateUseCount` on the decoy record
rather than deleting the alert.

That is not bookkeeping. It changes the engine's behaviour immediately and correctly: a decoy
with more than ten recorded legitimate uses can never reach the containment band, so it stops
being able to trigger an automated action while remaining visible in the report.

The cleaner fix is usually to re-plant: remove the contaminated decoy and create a new one
under a name the offending process does not match.

## Converting a real dormant account into a decoy

`New-TripwireDecoy -RegisterOnly -ObjectId <id>` records an existing object as a decoy without
creating or changing anything.

This is the strongest bait available — a real account with real history, real group
membership, and a real last-sign-in date that makes it look forgotten rather than fake. It is
also the only case where impossible travel can be evaluated, because a freshly planted decoy
has no history to travel from.

Two cautions. Strip its privileges first: a dormant *administrator* left with its role is a
decoy that also happens to be a live escalation path. And never register an account that
still has a mailbox somebody reads.

## Allowlist your own noise before you turn on alerting

Run `Watch-TripwireActivity` for a few days and look at what shows up. Anything that touches
every object in the directory — the vulnerability scanner, CMDB sync, a DLP crawler — belongs
in `baseline.suppressedActors` by directory object id.

Do this first. A deception deployment that pages five times in its first week is a deception
deployment that gets muted, and a muted detector is worse than no detector because everyone
believes it is on.

## Do not tell the directory which objects are decoys

There is no attribute, extension property, group, or naming convention that marks a decoy as
one. The inventory is a local file on the operator's machine.

The reason is direct: anything you write into the directory to identify decoys is readable by
the same enumeration you are trying to catch. A decoy that an intruder can filter out is a
decoy that only catches the intruders who were not paying attention.
