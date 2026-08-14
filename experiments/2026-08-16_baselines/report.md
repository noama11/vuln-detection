# WP3 — Baselines

Every row is scored with the identical paired metric on the identical case set: a case counts only when the vulnerable side is flagged `security_vulnerability_concern` **and** the fixed side is not. CIs are CVE-clustered bootstraps (2000 resamples).

| Arm | What it does | n scored | PFA | 95% CI | 2AFC | ROC-AUC | flag rate vuln / fixed |
|---|---|---|---|---|---|---|---|
| Method (spec reconstruction) | generate from spec, judge twice | 357 | **16.0%** | [12.3%, 20.2%] | 46.3% | 0.475 | 41.2% / 44.0% |
| B1 direct prompting | ask the same model 'is this vulnerable?' | 391 | **6.9%** | [4.5%, 9.5%] | 57.0% | 0.514 | 10.2% / 7.4% |
| B1s direct + spec | same, with the docstring supplied | 391 | **7.2%** | [4.7%, 10.0%] | 60.6% | 0.526 | 10.5% / 7.4% |
| B2 flawfinder | conventional static analyser | 392 | **2.8%** | [1.0%, 4.9%] | 87.5% | 0.514 | 18.4% / 15.8% |
| B3 always flag | no semantics | 392 | **0.0%** | [0.0%, 0.0%] | n/a | 0.500 | 100.0% / 100.0% |
| B3 never flag | no semantics | 392 | **0.0%** | [0.0%, 0.0%] | n/a | 0.500 | 0.0% / 0.0% |
| B3 coin flip (independent, p=0.5) | no semantics | 392 | **31.4%** | [27.0%, 36.0%] | 48.5% | 0.489 | 49.2% / 42.6% |
| B3 shorter side is vulnerable | no semantics | 392 | **4.3%** | [2.3%, 6.5%] | 16.0% | 0.464 | 4.3% / 21.4% |
| B3 longer side is vulnerable | no semantics | 392 | **21.4%** | [16.7%, 26.6%] | 89.2% | 0.536 | 21.4% / 4.3% |

## Reading the table

### Paired Flag Accuracy has a chance level of 25%, not 0%

This is the single most important thing WP3 establishes, and it invalidates the project's pre-registered decision bands.

A detector that flags each side independently with probability *p* scores

> PFA = P(flag vulnerable) x P(not flag fixed) = p(1 - p)

which is maximised at p = 0.5, giving **PFA = 25%** while using no information about the code whatsoever. The `always flag` and `never flag` rows score 0% not because they are worse detectors but because PFA punishes any detector that does not vary its answer — the metric rewards *asymmetry between the two calls*, and a coin flip supplies asymmetry for free.

The pre-registered bands (>=80% GO, 60-80% expand, <60% NO-GO, `HANDOFF.md` s1) were written as though chance were 0%. Against a true chance level of 25%, the 60% floor is not 'somewhat above chance' but roughly the midpoint between chance and perfect — a far more demanding bar than intended. The paper should state the chance level explicitly and report every PFA against it.

### The method scores below chance on its primary metric

Method **16.0%** vs coin flip **31.4%** (analytic chance 25.0%). The method is not merely failing to reach its target; it is below what a random detector achieves.

This replaces the write-up's section 4.3(c) argument, which reached a similar conclusion by multiplying marginal flag rates under an independence assumption it simultaneously denied. The comparison here needs no such assumption — it is a directly measured random baseline on the same cases.

**The two nulls answer different questions and both belong in the paper:**

- *Permutation null* (WP1, 17.4%): holding the judge's own flag rates and its between-call correlation fixed, does the label matter? Answer: no — 16.0% is inside that null. The method extracts no label information.
- *Coin-flip baseline* (this table, 31.4%): could a detector with no information do better by simply operating at a different point? Answer: yes, substantially. The method's operating point is also worse than random.

**Every baseline that matches or beats the method:**

- B3 coin flip (independent, p=0.5): 31.4%
- B3 longer side is vulnerable: 21.4%

### A length artefact, in the unexpected direction

`longer side is vulnerable` reaches **21.4%** using nothing but line counts, against **4.3%** for the opposite rule. 74.2% of pairs have identical line counts, so among the pairs that differ the vulnerable side is the longer one about five times out of six.

That is the reverse of the intuition that a fix adds a guard, and it is **partly an extraction defect rather than a property of CVE fixes**: 93 of 392 vulnerable snippets are brace-unbalanced (they over-run the target function and trail into the next one), against 3 of 392 on the fixed side — the vulnerable-side mirror of the fixed-side bug in `PILOT_INSIGHTS.md` Finding 1, and previously undocumented. See the threats note in `experiments/2026-08-17_spec-provenance/`. Restricting to cleanly extracted cases moves the method's PFA only from 16.0% to 15.8%, so this does not explain the null — but it does mean any length-correlated predictor on this corpus is partly measuring the extractor.

**flawfinder caveat.** It flags only 18.4% of vulnerable sides: the snippets are bare functions without headers, macros or types, so its pattern rules mostly find nothing. This is a fair measurement of *a static analyser applied to this corpus as extracted*, not of flawfinder on a complete build tree — state it that way in the paper.
