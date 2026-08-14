# Pre-registration — consensus arm as a confirmatory test

Written **before** the consensus (K=5) arm was run, and before the K=1 arm
finished. Recorded so the stratified claim can be read as a prediction that was
tested, not a subgroup found by searching.

## Status of the evidence at the time of writing

The single-candidate guard-contrast arm (`2026-08-19_guard-contrast`) was
partway through its run (137 of 391 cases). Interim, exploratory:

| stratum | decided | accuracy | p |
|---|---|---|---|
| all | 56 | 58.9% | 0.229 |
| fix adds an anticipatable defensive step | 28 | 67.9% | 0.087 |
| fix is domain-specific / other | 28 | 50.0% | 1.000 |

Nothing here is significant. It is a pattern, not a result.

## The hypothesis, and why it predicts that pattern

The method requires the reconstruction to contain a defensive step the vulnerable
version omits. An author working from the specification alone can only supply
such a step when it is one ordinary practice would suggest — a bounds check, a
null check, an initialisation. When the fix is a domain-specific correction
(reordering two locks, a magic constant, a protocol detail, a lifetime rule
specific to one subsystem), no reader of the specification could anticipate it,
and the method must be at chance by construction.

**Prediction: accuracy is above chance on the anticipatable stratum and at chance
on the remainder.** This is a dissociation, not a main effect, and the null
stratum is as much a part of the prediction as the positive one.

## What is fixed in advance

1. **The strata.** Defined in `experiments/common/cve_taxonomy.py`, written
   before any stratified number was computed. `ANTICIPATABLE` =
   `{adds_bounds_or_range_check, adds_null_or_error_check,
   initialisation_or_clearing}` = 196 of 392 cases; the remaining 196 are the
   null stratum. The classifier is **lexical, over the diff only, with no model
   involved**, so it cannot be contaminated by the system under evaluation.
   These sets will not be redefined after seeing the consensus results.
2. **The primary metric.** Directional accuracy on the decided subset: does the
   vulnerable reference receive a higher exposure score than the fixed one, given
   the same candidates? Chance is exactly 50%. Ties are reported as coverage and
   are never counted as successes or failures.
3. **The primary test.** Exact two-sided binomial against 50% on the
   anticipatable stratum, plus a CVE-clustered bootstrap CI. Significance
   threshold p < 0.05.
4. **The design.** K = 5 independent samples from the published, unmodified
   generator prompt at temperature 0.8; consensus rubric requiring a majority of
   samples to perform a step before it counts; one judge call per reference.

## What would falsify it

- Anticipatable stratum not significantly above 50% → the consensus arm has not
  demonstrated a working method, and the K=1 pattern was noise.
- Both strata significantly above 50% → the effect is not the predicted
  dissociation; something more general is happening and the mechanism account is
  wrong.
- The null stratum significantly above 50% → the mechanism account is wrong,
  whatever the other stratum does.

---

## UPDATE — the exploratory pattern did not survive (written before the K=5 result)

The K=1 arm finished. The interim pattern above was **noise**:

| stratum | interim (n=137) | **full (n=391)** | 95% CI | p |
|---|---|---|---|---|
| all | 58.9% (56 decided) | **48.8%** (170) | [41.4%, 56.3%] | 0.818 |
| anticipatable | 67.9% (28 decided) | **54.7%** (86) | [44.0%, 65.2%] | 0.451 |
| domain-specific / other | 50.0% (28 decided) | **42.9%** (84) | [32.6%, 53.7%] | 0.230 |

The anticipatable stratum regressed from 67.9% to 54.7% and its CI comfortably
includes 50%. **The single-candidate guard-contrast method does not work, and the
stratification does not rescue it.** This is exactly the failure mode the
pre-registration exists to catch: a 28-case subgroup that looked strong was
sampling variation, and treating it as a finding would have been wrong.

It also raises the bar for the K=5 arm honestly. The dissociation is no longer a
pattern awaiting confirmation — it is a hypothesis whose first test came back
null. K=5 tests a genuinely different mechanism (majority filtering across
independent samples, rather than one sample's idiosyncrasies), so it remains
worth running, but a positive result there would now be a **new** claim rather
than a replication, and it must be labelled as such.

### Why K=5 is still worth running

The 2x2 of candidate quality against judge question now reads:

| | published 5-way judge | narrow guard question |
|---|---|---|
| generated candidate | 16.0% PFA | 48.8% directional |
| **perfect candidate** | 14.6% PFA (ladder L1) | **84.4%** (WP5 contrastive) |

The bottom-right cell is the WP5 contrastive arm: when the candidate *is* the
patched function, comparing candidate-against-vulnerable is exactly comparing
fixed-against-vulnerable. So under the narrow question, going from a generated
candidate to a perfect one moves accuracy from 48.8% to 84.4%. **Under the right
question, reconstruction quality is the binding constraint** — which is precisely
what an ensemble is meant to improve. That is the motivation for K=5, and it is
independent of the stratification hypothesis that just failed.

### Second hypothesis, added now, to be tested on the K=5 data

Searching the full K=1 records for a better decision rule found one:

| decision rule | decided | coverage | accuracy | p |
|---|---|---|---|---|
| reference exposure (pre-registered primary) | 170 | 43% | 48.8% | 0.818 |
| count of missing steps | 200 | 51% | 51.0% | 0.832 |
| exposure + count | 244 | 62% | 51.2% | 0.749 |
| exposure, count as tiebreak | 251 | 64% | 51.4% | 0.705 |
| **net exposure (reference − candidate)** | 277 | **71%** | **56.7%** | **0.030** |

**This is not a result.** Five rules were tried and one came in at p = 0.030;
Bonferroni-corrected that is p ≈ 0.15. Reporting it as a finding would repeat the
mistake the update above documents, one section later.

It is, however, a *principled* rule rather than an arbitrary one, which is why it
is worth carrying forward rather than discarding. Subtracting the candidate's own
exposure controls for a per-call baseline: when a reconstruction is poor,
everything it is compared against looks defensively better, and that offset is
common to both judge calls. The difference removes it. The same logic explains
why the raw rule fails — 63% of vulnerable and 61% of fixed references are rated
exposure 0, so the raw score is mostly measuring whether the judge found anything
at all, not which side is worse.

**Pre-registered now, before the K=5 records exist**: net exposure
(`reference_exposure − candidate_exposure`, or for the consensus rubric
`target_exposure` differenced the same way if a candidate rating is available)
will be tested on the K=5 arm as a secondary hypothesis, one test, p < 0.05,
alongside the primary. The K=5 data are independent of the K=1 data that
suggested it, so a positive result there is a genuine replication rather than the
same search repeated.

## Reporting commitment

All three outcomes above will be reported. The K=1 arm is exploratory and will be
labelled as such; the K=5 arm is the confirmatory test. The overall (unstratified)
number will be reported alongside the stratified ones in every case, so a
dissociation cannot be presented as if it were a headline result for the method
as a whole.
