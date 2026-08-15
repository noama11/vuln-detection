# Chapter 15 — The two rescue arms on the corrected corpus

Chapters 9 and 11 both ran on the corpus ch. 13 showed was defective on the vulnerable side in 58% of cases. This re-measures both against clean snippets, with the rubric, seed and model held fixed. Predictions were fixed in `RESEARCH_LOG.md` ch. 15 before launch.

## Arm 1 — contrastive judge, generated candidate

The judge sees **both** references at once in randomised order and picks the one missing a guard. `neither` is permitted and scored as an abstention. Chance is 50%. This breaks premise constraint #2 and is reported as a diagnostic ceiling, not as the method.

| corpus | cases | decided | coverage | accuracy | 95% CI | CVEs |
|---|---|---|---|---|---|---|
| published (392) | 391 | 325 | 83.1% | **81.5%** | [77.2%, 85.8%] | 320 |
| **corrected (626)** | 626 | 533 | 85.1% | **82.4%** | [78.6%, 85.9%] | 453 |

Pre-registered prediction 75–88% with the CI excluding 50%: **confirmed**.

The strongest objection to ch. 9 was that the judge might be keying on the trailing fragments that only the *vulnerable* snippets carried. Those fragments are gone from this corpus. The accuracy did not fall.

## Arm 2 — consensus guard, K=5

Five independent reconstructions per case at temperature 0.8. The judge sees **one** reference at a time — premise intact. Directional accuracy: does the vulnerable reference score higher than the fixed one? Ties are coverage, never scored.

| corpus | cases | decided | coverage | accuracy | 95% CI | p vs 50% |
|---|---|---|---|---|---|---|
| published (392) | 391 | 175 | 44.8% | **50.3%** | [42.7%, 57.7%] | 1.0000 |
| **corrected (626)** | 626 | 236 | 37.7% | **65.3%** | [59.1%, 71.4%] | 0.0000 |

Pre-registered prediction 45–56% with the CI containing 50%: **NOT confirmed**.

> **This is a positive result.** Ensembling separates the pair on clean data, and the published null was measured against a contaminated baseline. It requires a seed replication before it is claimed — chapters 11 and 12 both produced marginal single-run results that did not survive one.

## The asymmetry, on clean data

| formulation | accuracy |
|---|---|
| judge sees **both** references (arm 1) | **82.4%** |
| judge sees **one** reference, 5 reconstructions (arm 2) | **65.3%** |
| gap | **17.1 points** |

Same model, same corpus, same generator, same seed. The raw gap is measured on a corpus that carries a strong length prior; the like-for-like comparison is the equal-length row of the stratification below.

---

# Figures quoted by the submission draft

Regenerated here so no number in the paper exists only in prose. These are not additional tests; the two pre-registered tests are above.

## §6.1 — pre-registered primary (non-duplicate subset)

Ch. 14 pre-registered the non-duplicate subset as the primary; the full set is descriptive.

| set | cases | decided | coverage | accuracy | 95% CI | p vs 50% |
|---|---:|---:|---:|---:|---|---:|
| **539 non-duplicate (primary)** | 539 | 205 | 38.0% | **66.8%** | [60.4%, 73.3%] | 1.6e-06 |
| 626 all (descriptive) | 626 | 236 | 37.7% | **65.3%** | [59.1%, 71.4%] | 3.2e-06 |

Contrastive diagnostic, same subset: 452 decided, **82.3%**, [78.6%, 85.9%].

## §6.2 — operating points and the margin curve

| decision rule | decided | coverage | accuracy | 95% CI |
|---|---:|---:|---:|---|
| target exposure | 236 | 37.7% | **65.3%** | [59.1%, 71.4%] |
| net exposure | 344 | 55.0% | **59.0%** | [53.8%, 64.2%] |

| minimum margin | decided | accuracy |
|---|---:|---:|
| >=1 | 236 | 65.3% |
| >=2 | 188 | 67.6% |
| >=3 | 82 | 63.4% |
| >=4 | 61 | 67.2% |

## §5.1 — the exposure score quantises to three values

| exposure | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|---|
| vulnerable | 79 | 5 | 7 | 14 | 362 | 8 | 148 | 3 |
| patched | 104 | 2 | 8 | 29 | 361 | 13 | 104 | 5 |

92% of all scores are exactly 0, 4 or 6. Ties: 390 (62.3%), of which 56 (14.4%) are both-zero.

Mean exposure: vulnerable 3.93, patched 3.63.

## §7.1 — length stratification

Corpus composition: 415 vulnerable-shorter, 148 equal, 63 vulnerable-longer. The rule *shorter side is vulnerable* is right on 86.8% of unequal pairs.

| stratum | method n | method | 95% CI | diagnostic n | diagnostic |
|---|---:|---:|---|---:|---:|
| vuln_shorter | 154 | **66.9%** | [59.3%, 74.5%] | 377 | 92.0% |
| equal | 54 | **68.5%** | [56.4%, 80.0%] | 100 | 77.0% |
| vuln_longer | 28 | **50.0%** | [30.0%, 69.2%] | 56 | 26.8% |

- **method** chooses the shorter side on 117/182 = 64.3% of unequal decided pairs.

- **diagnostic** chooses the shorter side on 388/433 = 89.6% of unequal decided pairs.

## §7.2 — docstring-leakage control

32 of 626 cases carry the heuristic leakage flag. On the 594 unflagged cases: **64.9%** (225 decided), against 65.3% overall.

