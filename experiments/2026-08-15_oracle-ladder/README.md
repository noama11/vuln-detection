# WP2 — The oracle ladder

**Objective**: find out *where* the detection signal is lost, by holding the
judge, the rubric and `prompt_sha` (`1de29ae28c7d`) fixed and varying only what
plays the role of `candidate_implementation`.

| Rung | Candidate | Question |
|---|---|---|
| L0 | the fixed snippet, verbatim | Can this judge flag the CVE given the true pair? |
| L1 | fixed snippet, locals renamed + comments stripped | How much of L0 was string alignment? |
| L2 | fixed snippet of a different, random case | What does the rubric flag on unrelated code? |
| L3 | the generated implementation | the method as published (`results/qwen_full/`, read in place) |

This replaces the frontier-model arm that the local-only budget rules out, and
is a better argument: it bounds what *any* judge could contribute, rather than
testing one more model.

**Rerun**:

```bash
bash scripts/serve_qwen.sh
python3 experiments/2026-08-15_oracle-ladder/run.py --rungs L0 L1 L2 --concurrency 8
python3 experiments/2026-08-15_oracle-ladder/report.py
```

~15 min per rung (389 cases x 2 judge calls). L3 is not re-run.

## Results

| Rung | n scored | PFA | 95% CI | ROC-AUC | flags vuln | flags fixed | degenerate |
|---|---|---|---|---|---|---|---|
| L0 oracle, verbatim | 360 | 39.7% | [34.4%, 45.2%] | 0.887 | 40.3% | 0.6% | 7.7% |
| L1 oracle, renamed | 364 | 14.6% | [10.9%, 18.6%] | 0.674 | 14.6% | 0.3% | 6.7% |
| L2 unrelated code | 1 | — | — | — | — | — | **99.7%** |
| L3 method | 357 | 16.0% | [12.3%, 20.2%] | 0.475 | 41.2% | 44.0% | 8.7% |

### 1. The judge depends on lexical overlap, contradicting its own rubric

Renaming local variables and stripping comments — changes the rubric explicitly
declares irrelevant (*"Different variable names … are **not** behavioral
differences"*) — costs **25 points of PFA (39.7% → 14.6%)** and **0.21 of AUC
(0.887 → 0.674)**. Semantics are identical across the two rungs; only surface
form differs. Roughly 52% of the entire fall from oracle to method happens at
this step.

The internal control makes it unambiguous. Within L1, cases with no renameable
locals (reformat only) score **34.6%** PFA (n=26); cases with 5+ renames score
**6.8%** (n=219).

This is the arm's primary contribution and it is not a claim the project could
previously make.

### 2. A perfect generator would not have moved the primary metric

L1 is a *perfect* reconstruction — the genuine patched function, merely renamed —
so it is the honest ceiling for any generator. **L1 = 14.6% vs the method's
16.0%**, statistically indistinguishable. Escalating the generator model tier or
feeding it more context cannot rescue PFA; the ceiling is already at the observed
value.

This supersedes §5 of the write-up, which attributes the failure to the generator
producing code structurally unlike the real thing. True, but not the binding
constraint on PFA.

**Do not overstate it**: L1 and L3 are *not* equivalent on ROC-AUC (0.674 vs
0.475). A perfect reconstruction does restore real ranking signal — the 5-way
taxonomy discards it before PFA sees it. Say "irrelevant to the metric as
pre-registered", not "irrelevant".

### 3. The 44% false-positive rate on patched code is an artefact of reconstruction

The judge flags the patched reference on **0.6%** of L0 cases and **0.3%** of L1
cases, against 44.0% at L3. The high false-positive rate §4.3(a) attributes to
the judge's security prior is manufactured entirely by comparing against a
generated candidate.

### 4. PFA discards signal the same data contain

At L0: AUC 0.887, PFA 39.7% — same judgements. Of the 215 L0 cases PFA scores as
misses, the judge called 106 `functional_mismatch`, 81 `equivalent` and 28
`quality_bug`: it saw the difference and declined to call it a security concern.
A primary metric requiring one specific category out of five throws away a much
stronger ranking signal. A metric-design finding, not a model finding.

### 5. L2 is a validity check, and it passes

Given an unrelated function as the candidate, the judge returns
`degenerate_generation` on **389/390 (99.7%)** of cases — rubric step 1 working
as designed. Only one case survives to be scored, so **L2's PFA is meaningless
and must not be quoted as a floor**. What L2 establishes is that the judge is not
indiscriminately pattern-matching: it detects off-topic input reliably.

## The synthesis

The failure is **over-determined**, and the paper should say so: the metric
discards signal (finding 4), the judge depends on lexical overlap (finding 1),
and reconstruction destroys what survives (L1 → L3 on AUC). No single fix
addresses all three, which is why the three rescue levers tried so far — better
model, more context, and now perfect reconstruction — each fail independently.

## Spec-sufficiency stratification (negative)

Splitting both rungs by a lexical proxy for whether the spec mentions any
identifier that differs between versions produces only a weak gradient at L3
(14.1% → 19.4% PFA) and none at L0. **The lexical proxy does not separate the
strata**, so the "the spec is insufficient" claim cannot rest on it; it needs the
semantic label from WP4(c). Reported here rather than dropped, because a
plausible stratification that fails is evidence too.
