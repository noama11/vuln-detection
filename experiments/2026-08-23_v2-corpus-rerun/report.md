# Chapter 14 — The method on the corrected corpus

Corpus `cases_v2/` (626 usable cases, 79% of the 792-case dataset) against the published corpus's 392 (49%). Configuration identical to the published arm — seed 1234, temperatures 0.2 / 0.0, `prompt_sha 1de29ae28c7d` — so the corpus is the only variable.

## Pre-registered primary

PFA on the non-duplicate subset, CVE-clustered bootstrap CI, 10k resamples. **Chance is 25%**, not 0%.

| set | cases | scored | CVEs | PFA | 95% CI (CVE-clustered) |
|---|---|---|---|---|---|
| non-duplicate (pre-registered primary) | 539 | 536 | 453 | **14.9%** | [12.0%, 18.0%] |
| all cases (descriptive) | 626 | 620 | 453 | **14.5%** | [11.7%, 17.3%] |

**Verdict against the pre-registration**: **below chance** — CI excludes 25% from below.

## Against the published arm

| | published (`qwen_full`) | this arm (`qwen_v2`) |
|---|---|---|
| cases run | 391 | 539 |
| scored | 357 | 536 |
| degenerate rate | 8.7% | 0.6% |
| PFA | 16.0% | 14.9% |
| ROC-AUC | 0.475 | 0.516 |
| flag rate, vulnerable side | 41.2% | 39.4% |
| flag rate, fixed side | 44.0% | 36.8% |
| independence baseline | 23.1% | 24.9% |

## Matched subset — the cleanest comparison available

The **343 cases present in both corpora**. Same cases, same CVEs, same prompts, same seed; only the snippets are repaired. Any difference here is attributable to the extraction fix alone, with the corpus expansion held out.

| corpus | cases | scored | CVEs | PFA | 95% CI (CVE-clustered) |
|---|---|---|---|---|---|
| published snippets | 343 | 324 | 286 | **15.7%** | [11.7%, 20.0%] |
| corrected snippets | 343 | 340 | 286 | **13.8%** | [10.1%, 17.8%] |

Cases whose paired-flag outcome changed sign: **63**.

PFA barely moves. **The directional quantities all change sign**, and that is the finding — on identical cases, with only the snippets repaired:

| | published snippets | corrected snippets |
|---|---|---|
| ROC-AUC | 0.473 | 0.524 |
| flag rate, vulnerable − fixed | -3.4pp | +3.2pp |
| permutation null mean | 17.4% | 12.2% |
| p(observed PFA ≥ null) | 0.871 | 0.140 |

The published arm sat **below** its own permutation null with the *fixed* side flagged more often than the vulnerable one — an anti-signal. On repaired snippets both reverse: AUC crosses 0.5, the vulnerable side is flagged more, and the observed PFA sits slightly above the null rather than below it. Corpus expansion is held out, so this is attributable to the extraction fix alone.

## Descriptive (not pre-registered, not promoted)

- Directional accuracy on the judge score: raw **27.1%**, tie-corrected **53.9%** (n=269, tie rate 49.8%)
- ROC-AUC: **0.516**
- Mean judge score: vulnerable **3.66**, fixed **3.71**, delta **+0.04**

### Degenerate generation by side

Ch. 13 predicted the *fixed*-side rate should fall, because the two sides were previously extracted by different code paths and now are not. This is the check on that attribution.

| side | published | this arm |
|---|---|---|
| vulnerable | 13 (3.3%) | 6 (1.0%) |
| fixed | 28 (7.2%) | 4 (0.6%) |

### Exchangeability

Permutation null over 10k label swaps: observed PFA **14.9%**, null mean **13.6%** (95% 11.4%–15.9%), p(observed ≥ null) = 0.1431, p(observed ≤ null) = 0.8893.

A *low* observed value against this null means the detector is anti-correlated with the label, which shows up as p(≥) near 1.

