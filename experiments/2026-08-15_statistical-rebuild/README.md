# WP1 — Statistical rebuild of the qwen3-32B arm

**Objective**: put defensible statistics under the numbers in
`experiments/2026-08-14_qwen3-32b-local-arm.md`, without re-running inference.

**What differs from the reference arm**: nothing is re-run. This reads
`results/qwen_full/*.json` read-only and recomputes. `scripts/compute_metrics.py`
and `reports/qwen_full_report.md` are untouched and still authoritative for the
figures they publish.

**Rerun**:

```bash
python3 experiments/2026-08-15_statistical-rebuild/run.py            # qwen_full
python3 experiments/2026-08-15_statistical-rebuild/run.py pilot ablation_baseline
```

Takes ~17 s (10k bootstrap resamples + 10k permutations). Output: `report.md`.

## Findings that change the paper

1. **The "below chance" claim in §4.3(c) does not survive a correct null, and
   should be dropped.** That section multiplies the two marginal flag rates to
   get a 23.1% baseline, then argues the observed 16.0% falls below it *because*
   the two judge calls are correlated. But multiplying the marginals is only
   valid under independence — the assumption the argument itself rejects. A
   permutation null that swaps both verdicts within a case preserves the
   correlation and centres at **17.4% [14.3%, 20.4%]**. The observed 16.0% sits
   inside it (p = 0.214).

   The replacement claim is cleaner and survives review: *paired flag accuracy is
   statistically indistinguishable from a null in which the reference shown to
   the judge has no effect on its verdict.*

2. **Pairwise Ranking Accuracy scores ties as failures.** 43.1% of scored cases
   tie. The published 26.3% is not comparable to a 50% chance line; the
   tie-corrected 2AFC is **46.3%** (n=203), CI [39.2%, 53.2%].

3. **ROC-AUC is not independent evidence.** The rubric binds score ranges to
   categories, and the category explains 57.9% of the score's entropy; on the
   scored subset 92.3% of score mass sits in {2,3,4,5} with a gap where 6–8
   should be. §4.3(a)/(b)/(c) is one demonstration seen three ways. WP5-R1
   decouples them.

4. **Clustered CIs are wider than the published binomial ones**, as expected:
   PFA [12.2%, 20.0%] vs the published [12.5%, 20.1%] — close here, but the
   resampling unit is now correct (320 CVE clusters, not 357 independent cases),
   so the number is defensible rather than lucky.

5. **No stratum rescues the method.** PFA ranges 10.3%–20.6% across repos,
   14.1%–18.2% across fix-size quartiles, and every ROC-AUC stays within
   [0.445, 0.507]. There is no subpopulation where the detector works — which is
   what makes the null a corpus-level claim rather than an averaging artefact.

## Reproduction gate

`run.py` refuses to be trusted unless it first reproduces the published
`n_cases=391`, `n_scored=357`, `PFA=0.160`, `ROC-AUC=0.475`, `n_degenerate=34`.
All five reproduce exactly.
