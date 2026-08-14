# WP2 — The oracle ladder

Judge, rubric and `prompt_sha` are held at the published values (`1de29ae28c7d`). The **only** thing that varies across rungs is what plays the role of `candidate_implementation`.

| Rung | Candidate | n scored | PFA | 2AFC (ties excl.) | ROC-AUC | flags vuln | flags fixed |
|---|---|---|---|---|---|---|---|
| **L0** | fixed snippet, verbatim | 360 | **39.7%** | 99.6% | 0.887 | 40.3% | 0.6% |
| **L1** | fixed snippet, locals renamed + comments stripped | 364 | **14.6%** | 98.5% | 0.674 | 14.6% | 0.3% |
| **L2** | fixed snippet of a different, random case | 1 | **100.0%** | 100.0% | 1.000 | 100.0% | 0.0% |
| **L3** | the generated implementation | 357 | **16.0%** | 46.3% | 0.475 | 41.2% | 44.0% |

## Confidence intervals (CVE-clustered bootstrap)

| Rung | PFA | 95% CI |
|---|---|---|
| L0 | 39.7% | [34.4%, 45.2%] |
| L1 | 14.6% | [10.9%, 18.6%] |
| L2 | 100.0% | [100.0%, 100.0%] |
| L3 | 16.0% | [12.3%, 20.2%] |

## Reading the ladder

**L2 is a validity check, and it passes.** Handed the fixed snippet of an unrelated case, the judge returns `degenerate_generation` on 389/390 (99.7%) — it recognises off-topic code as off-topic, exactly as rubric step 1 instructs. Only 1 case(s) survive to be scored, so L2's PFA is not a meaningful number and must not be quoted as a floor. What L2 establishes is that the judge is not simply pattern-matching anything put in front of it: it can tell when the candidate is unrelated.

**L0 -> L1 is the finding.** Renaming local variables and stripping comments — changes the judge's own rubric declares irrelevant — takes PFA from **39.7% to 14.6%** and ROC-AUC from **0.887 to 0.674**. The semantics are identical on both rungs; only the surface differs.

The rubric is explicit: *"Different variable names, different type/struct names, different helper function names, or different code style are **not** behavioral differences."* The judge does not follow it. Most of what looked like behavioural comparison at L0 was string alignment between a candidate and a reference that were byte-identical.

**L1 vs L3 is the claim the paper should make.** L1 is a *perfect* reconstruction — the real patched function, merely renamed — so it is the honest ceiling for any generator, however good. It scores **14.6%** [see CI table] against the method's **16.0%**.

On the pre-registered metric these are statistically indistinguishable: **a perfect generator would not have moved PFA.** Escalating the generator's model tier, or feeding it more context, cannot rescue this metric — the ceiling is already here.

This supersedes the write-up's section 5, which attributes the failure to the generator producing code structurally unlike the real thing. That is true, but it is not the binding constraint on PFA: hand the judge the real patched function and PFA does not improve.

**But the two rungs are *not* equivalent on ROC-AUC: 0.674 at L1 against 0.475 at L3.** A perfect reconstruction does restore substantial ranking signal — it is the 5-way taxonomy that discards it before PFA sees it. Do not state flatly that reconstruction quality is irrelevant; state that it is irrelevant *to the metric as pre-registered*, and worth roughly +0.199 AUC to a ranking-based one.

The failure is therefore over-determined, and the paper should say so: the metric discards signal (L0's AUC 0.887 vs PFA 39.7%), the judge depends on lexical overlap (L0->L1), and reconstruction destroys what survives (L1->L3). No single fix addresses all three.

**Where the ROC-AUC goes** (the metric least distorted by the 5-way taxonomy): 0.887 at L0 -> 0.674 at L1 -> 0.475 at L3. Roughly 51.7% of the total fall from oracle to method happens at the L0->L1 step, i.e. is attributable to removing lexical overlap rather than to reconstruction error.

**A separate metric-design finding.** At L0 the same data give ROC-AUC 0.887 but PFA 39.7%. The gap is the taxonomy: of the L0 cases PFA scores as misses, the judge mostly called the difference `functional_mismatch`, `equivalent_implementation_difference` or `quality_bug` — it saw the difference and declined to call it a security concern. A primary metric requiring one specific category out of five discards a ranking signal that is much stronger. This is a property of the pre-registered metric, not of the model.


## Outcome distributions

| Rung | vuln only (working) | fixed only (backwards) | both | neither |
|---|---|---|---|---|
| L0 | 143 (39.7%) | 0 (0.0%) | 2 (0.6%) | 215 (59.7%) |
| L1 | 53 (14.6%) | 1 (0.3%) | 0 (0.0%) | 310 (85.2%) |
| L2 | 1 (100.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| L3 | 57 (16.0%) | 67 (18.8%) | 90 (25.2%) | 143 (40.1%) |

## Degenerate rates

| Rung | degenerate | share |
|---|---|---|
| L0 | 30/390 | 7.7% |
| L1 | 26/390 | 6.7% |
| L2 | 389/390 | 99.7% |
| L3 | 34/391 | 8.7% |

## L1 internal control: does renaming volume matter?

| L1 subset | n scored | PFA |
|---|---|---|
| 0 identifiers renamed (reformat only) | 26 | 34.6% |
| 5+ identifiers renamed | 219 | 6.8% |

A gap here means the judge is keying on surface text rather than behaviour, in direct contradiction of its rubric.
