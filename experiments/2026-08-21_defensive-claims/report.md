# Chapter 12 — Defensive reconstruction with explicit guard claims

Premise intact: the Generator sees only `{language, docstring}`, the Judge sees one reference at a time and is never told which, no supervised labels. What changed is the generator's *instruction* (hardened rather than faithful, still spec-only) and the judge's *task* (per-claim verification rather than open-ended comparison).

## Pre-registered primary test

| score | n | decided | coverage | accuracy | 95% CI | p |
|---|---|---|---|---|---|---|
| severity-weighted omissions (pre-registered primary) | 379 | 210 | 55.4% | **57.1%** * | [50.5%, 63.8%] | 0.0451 |

## Alternative scores from the same records

Reported for completeness. These are **not** pre-registered; with three additional rules the corrected threshold is p < 0.0125, and any of them that looks good is a hypothesis for a fresh run, not a result — the lesson of chapters 10 and 11.

| score | n | decided | coverage | accuracy | 95% CI | p |
|---|---|---|---|---|---|---|
| count of omissions | 379 | 136 | 35.9% | **53.7%** | [45.0%, 62.5%] | 0.4404 |
| max single-omission severity | 379 | 147 | 38.8% | **58.5%** * | [50.6%, 66.4%] | 0.0474 |

## Secondary: stratified by what the fix does

Split is lexical, from the diff, no model involved (`experiments/common/cve_taxonomy.py`). The domain-specific stratum is the control: the method *cannot* work there, because no reader of the specification could anticipate the fix.

| stratum | n | decided | coverage | accuracy | 95% CI | p |
|---|---|---|---|---|---|---|
| fix adds an anticipatable defensive step | 192 | 111 | 57.8% | **60.4%** * | [51.0%, 69.9%] | 0.0363 |
| fix is domain-specific / other (control) | 187 | 99 | 52.9% | **53.5%** | [44.0%, 63.0%] | 0.5467 |

By fix category:

| fix category | n | decided | accuracy | p |
|---|---|---|---|---|
| other_modification | 123 | 66 | 60.6% | 0.109 |
| adds_bounds_or_range_check | 120 | 71 | 62.0% | 0.057 |
| adds_other_conditional | 43 | 25 | 44.0% | 0.690 |
| initialisation_or_clearing | 40 | 20 | 50.0% | 1.000 |
| adds_null_or_error_check | 32 | 20 | 65.0% | 0.263 |
| lifetime_free_or_lock | 11 | 6 | 33.3% | 0.688 |
| type_or_cast_change | 10 | 2 | 0.0% | 0.500 |

## Coverage–accuracy trade-off

| required score margin | answered | coverage | accuracy | p |
|---|---|---|---|---|
| >= 1 | 210 | 55.4% | 57.1% | 0.0451 |
| >= 2 | 177 | 46.7% | 57.6% | 0.0504 |
| >= 4 | 125 | 33.0% | 57.6% | 0.1070 |
| >= 6 | 75 | 19.8% | 53.3% | 0.6445 |
| >= 8 | 42 | 11.1% | 52.4% | 0.8776 |
| >= 10 | 21 | 5.5% | 57.1% | 0.6636 |

## Diagnostics — did the mechanism behave as designed?

- Guard claims per case: mean **4.0**, min 0, max 12
- Verdict mix over all 3022 claim checks: **performs** 51.3%, **omits** 37.6%, **not_applicable** 11.1%
- Mean severity-weighted score: vulnerable **7.81**, fixed **7.60**, delta **+0.22**
- Mean omissions per case: vulnerable **1.50**, fixed **1.49**

The `not_applicable` share is the load-bearing number: if it is near zero the judge is counting invented guards as real omissions, and if it is near one the checklist is not engaging with the reference at all. The delta is the detection signal — it must be clearly positive for the method to work.

