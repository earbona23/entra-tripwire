# The confidence engine

How EntraTripwire decides whether a decoy touch is an adversary or the tenant tripping over
its own furniture — and why it is allowed to act on some of those answers and not others.

- [The problem this solves](#the-problem-this-solves)
- [Suppression comes first](#suppression-comes-first)
- [The four signals](#the-four-signals)
- [Weights, and why these weights](#weights-and-why-these-weights)
- [Bands](#bands)
- [Withheld signals and the degraded flag](#withheld-signals-and-the-degraded-flag)
- [The baseline has a shelf life](#the-baseline-has-a-shelf-life)
- [Reading the whole window](#reading-the-whole-window)
- [The two structural invariants](#the-two-structural-invariants)
- [Worked examples](#worked-examples)
- [Mutation testing](#mutation-testing)
- [Tuning it for your tenant](#tuning-it-for-your-tenant)
- [Proposed: credential use as a fifth signal](#proposed-credential-use-as-a-fifth-signal)

---

## The problem this solves

Deception has an excellent signal-to-noise ratio in theory and a bad one in practice. In
theory nothing legitimate ever touches a decoy, so any touch is an intruder. In practice a
tenant is full of things that walk every object in the directory: vulnerability scanners,
CMDB synchronisation, DLP tooling, licensing scripts, a helpdesk agent searching for an
account, and — on day one, every time — the administrator who just planted the decoy.

A deception tool that pages on all of those gets switched off in a week. One that suppresses
them with a blunt rule misses the intrusion that arrives wearing the same shape. So the
question is never "was a decoy touched" but "how much of what we can observe is consistent
with an adversary, and how much of what we would need to observe could we not see."

## Suppression comes first

Before any scoring, two rules can zero a trip outright:

| Rule | What it catches |
|---|---|
| **Operator allowlist** (`baseline.suppressedActors`) | The tenant's own scanners and sync jobs, identified by directory object id |
| **Provisioning grace** | The planter touching the decoy within `ProvisioningGraceMinutes` (15) of planting it |

A suppressed trip is still returned, with its reason attached, and still appears in the
report. A suppression rule that *hides* evidence is indistinguishable from a bug that
*loses* it, and only one of those is something you would want to find out about later.

## The four signals

Each signal returns a raw strength in `0..1`, a weight, an availability flag, and a
rationale in words.

### (a) Decoy purity — has anything legitimate ever touched this decoy?

| Recorded legitimate uses | Raw |
|---|---|
| 0 | 1.00 |
| 1–2 | 0.50 |
| 3–10 | 0.20 |
| more than 10 | 0.00 |

`legitimateUseCount` is maintained by the operator on the decoy record. It is deliberately
**not** inferred from the logs, because inferring it would let an attacker who touches a
decoy repeatedly drive its own score down.

### (b) Origin anomaly — is this where the tenant works?

Strongest component wins:

| Component | Raw |
|---|---|
| Impossible travel vs the actor's last known position (> `ImpossibleTravelKph`, 900) | 1.00 |
| Country never seen in the baseline | 1.00 |
| Autonomous system never seen in the baseline | 0.80 |
| Country below `RareCountryShare` (1%) of baseline volume | 0.60 |
| Autonomous system below `RareAsnShare` (1%) | 0.50 |
| Otherwise | 0.00 |

Impossible travel is computed from a haversine distance, which under-estimates the real
flight path. The derived speed is therefore a **lower bound**: if the signal says 2,600 km/h,
the true figure is at least that, and the verdict cannot be an artefact of the distance model.

Autonomous system scores below country on its own because cloud egress legitimately moves
between ASNs while staying in the same country.

### (c) Cross-decoy fan-out — is this a sweep?

| Distinct decoys touched by the same actor inside `CorrelationWindowMinutes` (60) | Raw |
|---|---|
| 1 | 0.00 |
| 2 | 0.60 |
| 3 | 0.85 |
| 4 or more | 1.00 |

Distinct **decoys**, never events. An attacker retrying one decoy fifty times must not look
like a sweep across fifty decoys.

Actors that cannot be identified at all — no directory object id and no source address — are
never correlated with each other. Bucketing anonymous events together would manufacture
fan-out out of unrelated noise, and fan-out is the signal that carries a trip into the band
where containment becomes eligible.

### (d) Off hours — is this hour unusual *for this tenant*?

`raw = 1 - (signIns[hour] / signIns[busiest hour])`, from the tenant's own 24-hour histogram.
A tenant whose staff work nights is not permanently suspicious of itself.

## Weights, and why these weights

| Signal | Weight | Reasoning |
|---|---|---|
| DecoyPurity | **0.40** | The premise of the whole tool. If this signal is weak, nothing else should be able to carry a trip to an automated action. |
| OriginAnomaly | **0.25** | Strong, but noisy: travelling staff, VPN egress, cloud NAT. |
| CrossDecoyFanOut | **0.25** | The behavioural signal. Nothing legitimate walks a set of objects that no legitimate process knows exists. |
| OffHours | **0.10** | Deliberately weak. Real administrators work at 03:00, and a detector that treats the hour as strong evidence teaches its operators to close the alert. |

They sum to **1.00**, so confidence is a percentage of the maximum obtainable evidence and
two deployments' numbers mean the same thing.

## Bands

| Band | Score | What happens |
|---|---|---|
| **High** | ≥ 75 | Eligible for containment (still dry-run by default, still Pro, still `-Execute`) |
| **Medium** | 45–74 | Alert a human. Never an automated action. |
| **Low** | < 45 | Logged, visible in the report |
| **Suppressed** | 0 | A known-benign cause matched; shown with its reason |

## Withheld signals and the degraded flag

A signal that cannot be evaluated reports `Available = $false` and contributes **zero**. The
remaining weights are **not** renormalised.

That choice is the point. Renormalising would let a tenant with no baseline produce a
*higher* confidence than a tenant with one — a detector that gets more certain the less it
can see. Instead:

- a withheld signal can only push a score **down**;
- the trip is marked `Degraded` and names what was withheld;
- a degraded score is a **floor**, not a measurement;
- `Invoke-TripwireContainment` refuses to act on a degraded trip unless the operator passes
  `-AcceptDegraded`, which is recorded in the plan and the log.

Signals are withheld when: there is no baseline (origin, off hours), the baseline histogram
is missing or the wrong length (off hours), the log source carries no geographic enrichment at
all — directory audit records do not (origin), the touched object is not in the decoy inventory
(purity), **the record carries no usable timestamp** (off hours, and impossible travel), **the
baseline is stale or its age cannot be established** (origin, off hours — see below), or any of
the numbers these signals divide by turns out not to be a number:

| Value | Where it comes from | Withholds |
|---|---|---|
| `legitimateUseCount` | the decoy record, maintained by hand | purity |
| `generatedAt` | the baseline | origin, off hours |
| `totalSignIns` | the baseline | origin |
| a `countries` or `asns` count | the baseline | origin, when nothing else scored |
| an `hourHistogram` bucket | the baseline | off hours |
| a latitude or longitude in `actorLastSeen` | the baseline | impossible travel only |

Every one of those lives in a JSON file the documentation tells the operator to edit, and every
cast that reads one — `[int]`, `[double]`, and the `[double]` parameter binding in
`Get-TripwireDistanceKm` — **throws** on a word. It threw *inside a signal*, and scoring runs
per touch, so one bad character in one baseline field abandoned the whole batch: a run that
found intrusions returned nothing, and nothing is what a quiet tenant returns.

Note the direction in the fourth row. A country **absent** from the baseline means the tenant
has never been seen there and scores the full anomaly; a country whose count is **corrupt**
means nothing is known. Scoring the second as the first manufactures a 1.00 origin anomaly out
of a typo, so an unreadable count withholds instead — unless some other component already found
something, because the score is a floor and a real finding stands on its own. What must never
happen is the engine reporting a *normal* origin on the strength of a comparison nobody could
make.

## The baseline has a shelf life

`Get-TripwireBaseline` has always stamped `generatedAt` into the baseline file, and until now
nothing read it. A baseline from six months ago was used in silence — and two of the four
signals are statements about tenant history:

- *"this country has never appeared in 7,313 baseline sign-ins"* is a claim about a tenant that
  was measured once;
- *"03:00 runs at 4% of this tenant's busiest hour"* is a claim about a working pattern.

Tenants hire, open an office, change egress, move a team onto nights. Scored against an
obsolete baseline those two signals are not weaker evidence — they are evidence about a
different tenant.

| Age of the baseline | What happens |
|---|---|
| under `BaselineWarnAgeDays` (**15**) | Used, silently |
| 15 to 30 days | Used, and said once when it is loaded and once per scored batch |
| over `BaselineStaleAgeDays` (**30**) | Origin anomaly and off hours **WITHHELD**, trip `Degraded` |
| `generatedAt` missing or unparseable | **WITHHELD**. An age nobody can establish is not freshness |
| freshness limits missing from the policy | **WITHHELD**. `14 -gt $null` is `$true`, so this is refused rather than decided by accident |

**Why 30 days to withhold.** Entra retains sign-in logs for 30 days on P1/P2, and 30 is the
default `-Days` of a build. A baseline older than that summarises a period the tenant can no
longer produce the evidence for: not one of the sign-ins behind it is still in the log. That is
the first line here that is not arbitrary. A deployment that builds with `-Days 7` describes
less and should lower this to match.

**Why 15 days to warn.** Half the stale age — notice is given at the point where more of the
baseline's believable life is behind it than ahead of it, which leaves a fortnight to rebuild
before anything starts being withheld. The first calibration here was 7 days and it was wrong
for this module's own reason: an operator who rebuilds monthly would see it three weeks in four,
and a message that is nearly always on is a message that gets filtered out.

**Age is measured against the touch, not against the clock.** Re-analysing last month's logs
compares them with the baseline that was current *for them*, and a baseline built after an event
is not stale with respect to it at all: its history covers the period the touch came from. Only
a touch with no usable timestamp falls back to the clock, because there is nothing else to
anchor it to. It is also why the shipped fixtures do not rot.

The one place the clock is used deliberately is the advisory `Get-TripwireBaseline` prints when
it LOADS a baseline, because that is the moment the operator is looking and the question there
really is "is this file old now". That advisory is skipped for `-Demo`: those fixtures are frozen
in 2026-06 on purpose, so their age against today's date is a fact about the calendar rather
than about a tenant. Only the per-touch check decides whether a signal is withheld.

Withholding costs something, and that is the right price. The score drops, the trip is marked
`Degraded`, and `Invoke-TripwireContainment` refuses it — so a six-month-old baseline can no
longer carry anything to an automated action.

## Reading the whole window

A detector that reads part of its log and reports what it found there gives the one answer it
must never give by accident. The two sources are collected differently because only one of them
can be narrowed.

| Source | How it is read | Why |
|---|---|---|
| Sign-ins | **`$filter` naming the decoy identities**, server-side | The inventory is local and known: `userId`, `appId` and `userPrincipalName` are exactly the fields the sign-in matcher compares, so Graph can return the handful of records that matter instead of every sign-in in the window |
| Directory audits | **Time window, bisected on truncation** | Graph's `$filter` over `targetResources` does not express "any of these N objects", and a filter that approximated it would silently drop a decoy |

Three rules hold the narrowing honest:

1. **All or nothing.** If any decoy in the inventory has no object id, no application id and no
   UPN, it cannot be named in a filter — so the narrowing is abandoned for the whole source and
   the window is read in full. A filter that omits one decoy is a blind spot with no symptom:
   that decoy simply never trips again.
2. **A refused filter costs nothing but time.** If Graph rejects the query, the run falls back
   to the broad read and matches locally. The old behaviour is the safety net under the new one.
3. **Values are escaped twice** — OData doubles a quote, and the whole value is
   percent-escaped. A guest UPN contains `#`, and an unescaped `#` truncates the request URI at
   the fragment: the query still succeeds and that decoy's clause is simply not in it.

On both sides the page limit stops being the end of the story — the narrowed sign-in reads go
through the same windowed read as the audits. A window that reports more
pages than it was allowed is **halved and read again**, down to `-MinWindowMinutes` (5). Windows
are half-open — `ge start and lt end` — so two adjacent slices can neither overlap (which would
double every record between them) nor leave a gap (which would lose every record in it,
invisibly).

What is left over is named. A window that still fills every page at the floor goes into
`IncompleteWindows`, and `Watch-TripwireActivity` reports it **as an error** after the trips,
not as one more line of log:

```
Watch-TripwireActivity: This run did not read its whole window. 2 time window(s) still hold
unread records, so a decoy touch inside them is NOT in this result:
2026-06-14T00:00:00Z..2026-06-14T12:00:00Z, ... Re-run over those windows with a shorter -Days.
```

That message is deliberately outside the branch that runs when trips were found. Zero touches
from a window that was never read is exactly the case it exists for. `-AcceptPartialRead`
downgrades it to a warning, for a deliberate spot check on a huge window — and for nothing else.

**Known gap: the exported report does not carry this.** `Export-TripwireReport` is handed trips
and nothing else, so an HTML report written from a run that left a window unread looks exactly
like one written from a complete run. The error record is on the console; the artefact that gets
filed and read later is silent about it. Closing that means giving the report the run's coverage
explicitly and having it say *"this run did not state whether it read its whole window"* when it
is not given one — a report that cannot state its coverage should say so, rather than let the
reader assume it.

### What has not been verified against a tenant

The filter *shape* is tested against mocks: that every decoy identifier appears in some query,
that no OR group mixes two fields, that a `#` is escaped, that a large inventory is split, and
that a refused filter falls back and still finds the touch. What mocks cannot establish is
whether a particular Graph build accepts `createdDateTime ge … and (userId eq … or userId eq …)`
on `auditLogs/signIns` in every tenant and licence combination.

That is why the fallback exists and why it is triggered by *any* failure of the narrowed read
rather than by a list of error codes. The worst case is the behaviour this module had before:
one broad read of the window, matched locally. If a tenant ever shows a narrowed query that
*succeeds* while returning fewer records than the broad read — a filter accepted and
mis-applied rather than rejected — that is the one failure this design does not catch, and the
remedy is a run with `-Days 1` compared against the same window read both ways.

## The two structural invariants

Both fall out of the weights, and both are enforced by tests.

**1. No single signal can reach the containment band alone.**
The largest weight is 0.40, so the most any one signal can contribute is 40 — well below 75.
An anomaly on its own is never enough to act on; High means *corroborated*.

**2. A contaminated decoy can never reach the containment band.**
If purity is 0, the remaining weights total 0.60, so the maximum obtainable score is 60.
Containment cannot fire on a decoy that has stopped being a decoy — however anomalous the
origin, however wide the sweep, however strange the hour.

## Worked examples

Every number below is produced by the shipped fixtures and asserted in `tests/Demo.Tests.ps1`.
Run `Watch-TripwireActivity -Demo` to reproduce them.

| Score | Band | What happened |
|---|---|---|
| **99.6** | High | A decoy service account is **used to sign in** at 03:12 UTC from a country and an ASN the tenant has never used, and the same principal touches four more decoys within eight minutes. Purity 40 + origin 25 + fan-out 25 + off-hours 9.6. |
| **74.6** | Medium | The same sweep, seen in the **directory audit log** instead. Audits carry no geographic enrichment, so the origin signal is withheld: 40 + 0 + 25 + 9.6, marked `Degraded`. Containment refuses it. |
| **74.6** | Medium | A dormant administrator account converted into a decoy signs in from Frankfurt 2h20 after signing in from New York. **Impossible travel** at ~2,660 km/h, but only one decoy touched, so no fan-out. An alert for a human, not an action. |
| **40.3** | Low | A helpdesk agent opens a decoy in the portal at 15:10 on a Tuesday. Pristine decoy, normal hour, no fan-out. |
| **34.6** | Low | **The same sweep, on the contaminated decoy.** Identical actor, identical minute, identical fan-out — and 40 points lower, because `hr-export` has 14 recorded legitimate uses. This is the engine's whole thesis in one row. |
| **0** | Suppressed | The administrator who planted the decoy, touching it two minutes later. |
| **0** | Suppressed | The tenant's vulnerability scanner, sweeping the directory at 04:00 as it does every night. |

## Mutation testing

The suite being green proves the tests ran. It does not prove they would notice if the
engine were wrong. `scripts/mutation-test.ps1` introduces one real defect at a time and
requires the suite to go red.

`-Only <names>` runs a subset, for working on one area without paying for the whole set. A
filtered run says so in its summary and refuses a name that matches no mutant, because a green
"8 of 8 killed" that reads like the whole suite is the same lie as a truncated log read. CI
passes nothing, so the gate stays the full set.

It reports three outcomes, not two: **Killed**, **SURVIVED**, and **NOT APPLIED**. The third
exists because a mutation that fails to apply produces a green run that is identical to a
surviving mutant — and identical in the flattering direction, since the harness would
otherwise report "killed" for a defect it never introduced. Every edit is verified against
the file contents before and after, and a mutation that does not apply fails the run.

Current result — **47 mutants, 47 killed, 0 survived, 0 not applied.** Two of them survived the
first run and are the reason two tests exist that otherwise would not:

| Mutant that survived | The hole it exposed |
|---|---|
| `withheld-still-counts` (`$effective = $Raw`) | Every caller happened to pass `Raw = 0` alongside `Available = $false`, so the rule "unavailable contributes zero" was never actually exercised. Now tested directly on `New-TripwireSignal`. |
| `band-boundary` (`-ge` → `-gt`) | No test produced a score of exactly 75, so the inclusivity of the threshold was undefended. Now tested with a case that lands on it precisely. |

Sixteen of the forty-seven cover collection coverage and baseline freshness, and they are written
around one shape of defect rather than around the lines that happen to be there — a control that
approves when its source returns nothing:

| Mutant | The defect it introduces |
|---|---|
| `truncation-not-signalled` | A read that stopped at the page limit tells its caller it finished |
| `window-not-bisected` | A window too dense to read is given up on instead of split |
| `unread-window-not-named` | A window that could not be read is dropped from the accounting |
| `queued-windows-discarded` | The windows still queued at the request ceiling are thrown away rather than reported |
| `partial-read-not-reported` | The gap is announced quietly instead of as an error |
| `signin-filter-drops-a-decoy` | A decoy that cannot be named in the filter leaves the query |
| `signin-filter-unescaped` | A `#` in a UPN truncates the URI and the clause vanishes |
| `filter-failure-not-recovered` | A refused filter leaves the source unread instead of falling back |
| `baseline-staleness-ignored` | A six-month-old baseline is believed |
| `baseline-age-unknown-assumed-fresh` | A baseline with no readable `generatedAt` passes as current |
| `freshness-limits-null-waved-through` | A policy that lost the limits decides by `$null` comparison |
| `baseline-load-age-silent` | Loading a stale baseline says nothing |
| `totalsignins-unchecked` / `histogram-bucket-unchecked` / `coordinates-unchecked` | A hand-edited field that is not a number throws from inside a signal and abandons the batch |
| `unreadable-count-scored-as-unseen` | A corrupt baseline count is scored as a country never seen |

## Tuning it for your tenant

`Get-TripwirePolicy` returns the calibration as data; pass a modified copy to any scoring
command.

```powershell
$policy = Get-TripwirePolicy -Override @{
    ImpossibleTravelKph      = 1200   # a tenant with a lot of long-haul travel
    CorrelationWindowMinutes = 120    # a slower, more patient adversary
    BaselineStaleAgeDays     = 7      # a baseline rebuilt nightly, believed for a week
    BaselineWarnAgeDays      = 3
}

Watch-TripwireActivity -Policy $policy
```

An override replaces whole top-level keys, and the freshness limits are no exception: a policy
that reaches the engine without a usable `BaselineStaleAgeDays` has the origin and off-hours
signals **withheld** rather than scored, because `14 -gt $null` is `$true` and a limit that
decides the question by accident is not a limit.

Raising a weight is not free: the invariants above are consequences of these numbers, not
separate rules. If you move `DecoyPurity` below 0.25 you lose invariant 2, and the tests
will tell you so.

## Proposed: credential use as a fifth signal

**Status: designed and calibrated, NOT implemented.** The reasoning is here so it can be argued
with before any number moves; the cost of landing it is at the bottom and it is the reason it
did not land with the rest of this work.

### The observation

`ConvertTo-TripwireTouchFromSignIn` already records whether the sign-in succeeded, and every
touch already records which log it came from. The engine scores neither. So the strongest
observation this tool can make — *somebody authenticated as a decoy* — is scored exactly like
the weakest one, a helpdesk agent opening the decoy in the portal.

The difference is not a matter of degree. A decoy user is created with a random password that is
generated, sent to Graph and discarded, so nobody can sign in as it; an application decoy's
secret is placed where an intruder looks and a colleague does not (see
[deception-design.md](deception-design.md)). Enumeration is something a scanner does by
accident. **Authentication is not.**

Today that difference shows up only by accident of telemetry: audit records carry no geographic
enrichment, so audit-sourced touches lose the origin signal and land about 25 points lower than
sign-in-sourced ones. That gap is a property of Graph's log schema, not a judgement about
evidence — and in the shipped fixtures it happens to point the right way, which is exactly the
kind of coincidence that stops being true on somebody else's tenant.

### The signal

| Observation | Raw | Reasoning |
|---|---|---|
| Successful sign-in as a decoy principal | **1.00** | The planted credential was held, and it worked. There is no benign path to this |
| Failed sign-in as a decoy principal | **0.60** | The credential was *tried*. Weaker on purpose: decoys are named to look plausible, so a username spray can reach one without ever having seen the seeded secret |
| Any directory-audit touch | **0.00** | Enumeration. This is the behaviour the other four signals are already calibrated against |
| No usable `source` on the touch | *withheld* | |

Deliberately only three tiers, all derivable from the touch itself. The tempting fourth —
"somebody *modified* the decoy: reset its password, added a credential, granted it a role" —
needs a list of `activityDisplayName` values to recognise, and an activity missing from that list
would score 0.00 while looking evaluated. That is the silent-coverage shape this engine spends
most of its code avoiding, and it is not worth buying one tier with it.

### Recalibration

| Signal | Now | Proposed |
|---|---|---|
| DecoyPurity | 0.40 | **0.35** |
| OriginAnomaly | 0.25 | **0.20** |
| CrossDecoyFanOut | 0.25 | **0.20** |
| CredentialUse | — | **0.20** |
| OffHours | 0.10 | **0.05** |
| **Sum** | 1.00 | **1.00** |

Both structural invariants survive, and they are the constraint that fixes these numbers rather
than taste:

1. **No single signal reaches the containment band alone.** Largest weight 0.35 → 35 < 75. ✓
2. **A contaminated decoy can never reach High.** With purity at 0 the rest totals 0.65 → 65 < 75. ✓

A third falls out and is worth stating: **purity plus credential use is 55, still Medium.** A
confirmed sign-in with a planted credential on a pristine decoy is *not* enough for an automated
action on its own — it needs a third signal, which is the same rule applied to every other
signal here. What it does buy is that the observation stops being invisible: a lone decoy
credential sign-in from an ordinary country at an ordinary hour scores 55 (Medium, alert a
human) where today it scores 40 (Low, a line in the report).

### What landing it costs

Not the implementation — the published numbers:

- **`README.md`** and the [worked examples](#worked-examples) above publish 99.6 / 74.6 / 40.3 /
  34.6. Every one of them moves. The 99.6 case becomes ≈99.8; the contaminated-decoy row, which
  is the engine's whole thesis, changes by the new purity weight rather than by 40.
- **`tests/Demo.Tests.ps1`** asserts those exact numbers on purpose — "a README that documents a
  score the code no longer produces is a lie with a long half-life". It is the regression lock,
  so it has to be rewritten in the same commit.
- **`tests/Scoring.Tests.ps1`** pins 40, 65 and a case landing exactly on 75; the last needs a
  new histogram to land on the boundary again.
- **`Assert-TripwirePolicy`** must learn the fifth weight. If it does not, a policy handed in
  without `CredentialUse` leaves it `$null`, `[double]$null` is 0, and the signal reports
  `Available = $true` at full raw strength while contributing nothing — with the trip **not**
  marked degraded. That is the precise defect that function was written for.
- **`src/EntraTripwire/Demo/signins.json`** needs a failed decoy sign-in to exercise the 0.60
  tier, which also changes the trip count the demo tests assert.
- **New mutants**: a read scored as a credential use, a failure scored as a success, and the
  withheld case scored as a read.

Those files belong to other work in flight. A weight change that lands without them is a red
suite and a README publishing scores the code does not produce, which is worse than the gap it
closes.
