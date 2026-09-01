# The confidence engine

How EntraTripwire decides whether a decoy touch is an adversary or the tenant tripping over
its own furniture — and why it is allowed to act on some of those answers and not others.

- [The problem this solves](#the-problem-this-solves)
- [Suppression comes first](#suppression-comes-first)
- [The four signals](#the-four-signals)
- [Weights, and why these weights](#weights-and-why-these-weights)
- [Bands](#bands)
- [Withheld signals and the degraded flag](#withheld-signals-and-the-degraded-flag)
- [The two structural invariants](#the-two-structural-invariants)
- [Worked examples](#worked-examples)
- [Mutation testing](#mutation-testing)
- [Tuning it for your tenant](#tuning-it-for-your-tenant)

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
is missing or malformed (off hours), the log source carries no geographic enrichment at all —
directory audit records do not (origin), or the touched object is not in the decoy inventory
(purity).

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

It reports three outcomes, not two: **Killed**, **SURVIVED**, and **NOT APPLIED**. The third
exists because a mutation that fails to apply produces a green run that is identical to a
surviving mutant — and identical in the flattering direction, since the harness would
otherwise report "killed" for a defect it never introduced. Every edit is verified against
the file contents before and after, and a mutation that does not apply fails the run.

Current result — 17 mutants, 17 killed, 0 survived, 0 not applied. Two of them survived the
first run and are the reason two tests exist that otherwise would not:

| Mutant that survived | The hole it exposed |
|---|---|
| `withheld-still-counts` (`$effective = $Raw`) | Every caller happened to pass `Raw = 0` alongside `Available = $false`, so the rule "unavailable contributes zero" was never actually exercised. Now tested directly on `New-TripwireSignal`. |
| `band-boundary` (`-ge` → `-gt`) | No test produced a score of exactly 75, so the inclusivity of the threshold was undefended. Now tested with a case that lands on it precisely. |

## Tuning it for your tenant

`Get-TripwirePolicy` returns the calibration as data; pass a modified copy to any scoring
command.

```powershell
$policy = Get-TripwirePolicy -Override @{
    ImpossibleTravelKph      = 1200   # a tenant with a lot of long-haul travel
    CorrelationWindowMinutes = 120    # a slower, more patient adversary
}

Watch-TripwireActivity -Policy $policy
```

Raising a weight is not free: the invariants above are consequences of these numbers, not
separate rules. If you move `DecoyPurity` below 0.25 you lose invariant 2, and the tests
will tell you so.
