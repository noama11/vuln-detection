# Consolidated findings — what the paper should claim, and what to fix

Companion to `experiments/2026-08-14_qwen3-32b-local-arm.md`. That document
reports the corpus-scale null correctly; this one establishes *why*, corrects
three claims in it that will not survive review, and adds two confounds it does
not mention.

Every arm here is additive. `scripts/`, `cases/`, `results/`, `reports/`,
`pilot/` and `.claude/` are unmodified, and `prompt_sha` still resolves to
`1de29ae28c7d` on every arm that intends to reuse the published rubric.

| Arm | Directory | Inference |
|---|---|---|
| WP1 statistical rebuild | `2026-08-15_statistical-rebuild/` | none |
| WP2 oracle ladder | `2026-08-15_oracle-ladder/` | 3 × 389 cases |
| WP3 baselines | `2026-08-16_baselines/` | 2 × 392 cases + CPU |
| WP4 spec provenance | `2026-08-17_spec-provenance/` | none (part a) |
| WP5 contrastive judge | `2026-08-18_rescue-arms/` | 2 × 391 cases |

---

## 0. The result in one table

Everything, on the same 392-case corpus and the same model:

| Formulation | Sees | Score | Chance |
|---|---|---|---|
| **Contrastive, both versions** | both | **84.4%** [80.1, 88.4] | 50% |
| Coin flip | — | 31.4% | 25% |
| `longer side is vulnerable` | both (line counts) | 21.4% | 25% |
| **Spec reconstruction (the method)** | one + spec | **16.0%** [12.3, 20.2] | 25% |
| Oracle: perfect reconstruction, renamed | one | 14.6% | 25% |
| Direct prompt + spec | one + spec | 7.2% | 25% |
| Direct prompt | one | 6.9% | 25% |
| flawfinder | one | 2.8% | 25% |

**Every formulation that examines one version at a time lands at or below chance.
The one that compares both versions directly reaches 84%.**

That is the paper. The information needed to separate a pre-patch from a
post-patch function is present in this corpus, and Qwen3-32B can extract it at
84% (p < 1.1e-36). The method's 16% is therefore a property of the **task
formulation**, not of the model, the corpus, or the difficulty of the problem.

The negative result changes from *"spec reconstruction does not work"* to *"spec
reconstruction does not work, and here is proof the failure is in the formulation
rather than the data — together with a measurement of exactly what the
formulation costs."*

---

## 1. The headline claim, restated

The current claim is *"spec reconstruction fails; the generator's output differs
from both references for reasons unrelated to the CVE"* (§5). That is true but
under-powered, because it invites the obvious rebuttal: **use a better
generator**. The write-up answers this by pointing at the Qwen-vs-Haiku null,
which is weak evidence — two mid-tier models agreeing tells you little about a
frontier one.

The oracle ladder answers it decisively and without API spend. Replace the
generated candidate with **the genuine patched function, with local variables
renamed** — a perfect reconstruction, the ceiling for any generator that will
ever exist:

| Rung | Candidate | PFA | 95% CI | ROC-AUC |
|---|---|---|---|---|
| L0 | patched function, verbatim | 39.7% | [34.4%, 45.2%] | 0.887 |
| **L1** | **patched function, renamed** | **14.6%** | **[10.9%, 18.6%]** | **0.674** |
| L3 | generated from spec (the method) | 16.0% | [12.3%, 20.2%] | 0.475 |

**A perfect generator does not move the primary metric.** L1 ≈ L3. The method is
not limited by generator capability, by context, or by reconstruction fidelity.

## 2. The mechanism: the judge is keying on surface form

L0 and L1 are semantically identical — same function, same behaviour. The only
difference is that L1 renames local variables and strips comments, changes the
judge's own rubric calls irrelevant:

> "Different variable names, different type/struct names, different helper
> function names, or different code style are **not** behavioral differences"
> — `.claude/agents/vuln-judge.md`

That alone costs **25 points of PFA and 0.21 of AUC**, about 52% of the entire
fall from oracle to method. The internal control within L1 removes any doubt:

| L1 subset | n | PFA |
|---|---|---|
| 0 identifiers renamed (reformat only) | 26 | **34.6%** |
| 5+ identifiers renamed | 219 | **6.8%** |

**The LLM judge's apparent ability to compare two implementations behaviourally
is, on this corpus, largely lexical.** This is the paper's most transferable
contribution — it generalises well beyond spec reconstruction to any
LLM-as-judge code-comparison design, and it is measured, not argued.

## 3. The failure is over-determined

Three independent causes, each sufficient on its own:

1. **The metric discards signal.** At L0 the same judgements give AUC 0.887 and
   PFA 39.7%. Of the 215 L0 cases PFA scores as misses, the judge called 106
   `functional_mismatch`, 81 `equivalent`, 28 `quality_bug` — it saw the
   difference and declined to call it a security concern. Requiring one specific
   category out of five throws away a strong ranking signal.
2. **The judge is lexically dependent** (§2 above).
3. **Reconstruction destroys what survives**: AUC 0.674 at L1 → 0.475 at L3.

No single fix addresses all three. That is why better model, more context, and
now perfect reconstruction each failed independently.

## 4. Three claims in the write-up to correct before submission

### 4.1 "It underperforms its own chance baseline" (§4.3c) — drop it

§4.3(c) multiplies the two marginal flag rates (0.412 × 0.560 = 23.1%), notes
16.0% is lower, and infers the two judge calls must be positively correlated.
The multiplication is valid only under independence — the assumption the argument
then denies. A reviewer will reject this.

The permutation null swaps both verdicts within a case, preserving whatever
correlation exists, and centres at **17.4% [14.3%, 20.4%]**. The observed 16.0%
sits **inside** it (p = 0.21).

Replace with: *paired flag accuracy is statistically indistinguishable from a
null in which the reference shown to the judge has no effect on its verdict.*
Cleaner, stronger, and assumption-free.

### 4.2 Paired Flag Accuracy has a chance level of 25%, not 0%

A detector flagging each side independently with probability *p* scores
`p(1−p)`, maximised at p = 0.5 → **25%**. Measured coin flip: **31.4%**. The
method: 16.0%.

So the method *is* below chance — but for this reason, not §4.3(c)'s. Two
consequences:

- The pre-registered bands (≥80% GO, 60–80% expand, <60% NO-GO) were calibrated
  as though chance were zero. Against a true chance level of 25%, the 60% floor
  sits near the midpoint between chance and perfect.
- `always flag` and `never flag` both score **0%** — not because they are worse
  than a coin flip, but because PFA rewards *asymmetry between the two calls*.
  Worth a sentence: a metric that looks like accuracy does not behave like one.

### 4.3 §4.3(a)/(b)/(c) are not three independent demonstrations

The rubric binds score ranges to categories, and the category explains **57.9%**
of the score's entropy; on scored cases 92.3% of score mass sits in {2,3,4,5}
with a gap where 6–8 should be. ROC-AUC is substantially redundant with PFA.
Present them as one demonstration examined three ways.

Also: **Pairwise Ranking Accuracy counts 43.1% ties as failures.** The published
26.3% is not comparable to a 50% chance line. Tie-corrected 2AFC is **46.3%**
(n=203), CI [39.2%, 53.2%]. Report both.

Finally, the CIs in §4.1 are binomial over cases that cluster by CVE and repo
(357 cases, 302 CVEs, 51% from `torvalds/linux`). CVE-clustered bootstrap CIs:
PFA [12.2%, 20.0%], AUC [0.442, 0.509].

## 5. Two confounds the write-up does not mention

### 5.1 The specifications are derived from the vulnerable code

Identifiers unique to one side of the fix, counted against the docstring:

| | mentions | cases leaning this way |
|---|---|---|
| vulnerable-only | **470** | 94 |
| fixed-only | **127** | 41 |

A **3.7× asymmetry**; sign test **p = 2.9×10⁻⁶**. `D.zip`'s `scope` entries carry
line numbers into `vulnerable.<ext>`, so the documentation was generated against
the pre-patch file.

This survives the §3 leakage audit, which removed docstrings *stating* the fix
but could not remove the fact that the spec was written by reading the vulnerable
function. It predicts both anomalies the write-up reports without explaining:
ROC-AUC below 0.5, and the −0.18 score gap favouring the vulnerable side.

**Not only a dataset artefact.** In deployment a project's docstring is written
alongside the code it documents — the vulnerable version, right up until the
patch lands. Any spec-reconstruction detector inherits this bias wherever the
spec is not authored independently of the implementation. That is a genuine,
transferable finding, and it belongs in the paper as a design constraint on the
whole method family, not just as a threat.

### 5.2 An undocumented extraction defect, mirror of PILOT_INSIGHTS Finding 1

`extract_cases.py` slices the vulnerable snippet from the dataset's literal
`scope.start`/`scope.end` range, which frequently over-runs the target function:

| Side | balanced | malformed |
|---|---|---|
| vulnerable | 281 | **111 (28.3%)** |
| fixed | 389 | 3 (0.8%) |

All carry `extraction_status: "ok"` and sit inside every published metric.
Example `C_102__0`: the vulnerable snippet ends part-way into
`shmem_show_options`, the function *after* the target.

**It does not explain the null** — PFA moves 16.0% → 15.8% on cleanly extracted
cases — but it belongs in Threats, and it means any length-correlated predictor
on this corpus is partly measuring the extractor. Related: `longer side is
vulnerable` scores 21.4% PFA on line counts alone.

## 6. Baselines

| Arm | PFA | ROC-AUC | Note |
|---|---|---|---|
| Coin flip | 31.4% | 0.489 | analytic chance = 25% |
| `longer side is vulnerable` | 21.4% | 0.536 | line counts only; partly the extraction defect |
| **Method** | **16.0%** | 0.475 | |
| Direct prompt + spec | 7.2% | 0.526 | flags only 10.5% of vulnerable sides |
| Direct prompt | 6.9% | 0.514 | |
| flawfinder 2.0.20 | 2.8% | 0.514 | flags 18.4% of vulnerable sides |
| always / never flag | 0.0% | 0.500 | PFA punishes constant predictors |

**Direct prompting is worse than the method, and both are at chance on AUC**
(0.514 / 0.526 versus 0.475). Asked "is this function vulnerable?" about a single
function, the model says yes only ~10% of the time and gets no better than chance
at telling the two versions apart. Supplying the specification barely helps
(+0.3 points of PFA, +0.012 AUC).

This matters for the paper in two ways. It answers the obvious reviewer question
*"why not just ask the model?"* with a measured number. And it shows the method's
failure is **not** peculiar to spec reconstruction: it is what happens to every
single-version formulation on paired CVE data, which replicates the known
paired-metric collapse in the literature while adding a mechanism.

flawfinder caveat: the snippets are bare functions with no headers, macros or
types, so its pattern rules mostly find nothing. Report it as *a static analyser
applied to this corpus as extracted*, not as flawfinder's general capability.

## 6b. The contrastive result — the paper's positive core

One call, both versions present in randomised order, one narrow question: *does
one side omit a defensive step the other performs?* `neither` permitted and
scored as an abstention.

| Mode | decided | accuracy | 95% CI | abstained |
|---|---|---|---|---|
| oracle (both snippets only) | 308/391 | **84.4%** | [80.1%, 88.4%] | 21.2% |
| generated (+ reconstruction as context) | 325/391 | 81.5% | [77.2%, 85.8%] | 16.9% |

Exact binomial against 50%: **p < 1.1×10⁻³⁶**. CVE-clustered bootstrap.

**Both known artefacts are ruled out**, which is essential before claiming this:

| Check | Result |
|---|---|
| Extraction defect | clean 84.8% vs malformed 83.7% — no effect |
| Length | equal-length pairs **89.0%**, unequal 66.7% — *opposite* of a length heuristic |
| Position | always-A would score 47.6%; order randomised per case |

Supplying the reconstruction changes nothing (81.5% vs 84.4%), confirming WP2:
the reconstruction is not where the value is.

### What it does not show — state this plainly

The contrastive arm is **not a deployable detector.** It needs *both* the pre-
and post-patch versions, which is precisely what a real detector does not have —
at detection time only one version exists. It is a diagnostic and a ceiling, not
a method. Presenting it as a working vulnerability detector would be wrong and a
reviewer will catch it.

The honest framing: **the gap between 84% (both versions, right question) and
16% (one version, wrong question) is the paper's quantified statement of what the
formulation costs.**

## 7. A hypothesis that failed, reported anyway

The natural explanation — *the spec is silent about what the fix changed* — has
real support: **47.7% of specs mention none of the identifiers that differ
between the two versions**, and median coverage is 4.3%.

But stratifying the results by that lexical proxy **does not separate the
strata**: L3 PFA runs 14.1% → 16.2% → 19.4% across increasing coverage, and L0
shows no gradient at all. The lexical proxy is too crude to carry the claim. It
needs a semantic label (does the spec state the property the fix restores?) to
stand, and until then the sufficiency argument should be presented as motivated
but unconfirmed.

## 8. Recommended paper structure

| Section | Source |
|---|---|
| Method | unchanged, plus the note that score is category-bound |
| Main result | WP1 — clustered CIs, permutation null, tie-corrected 2AFC |
| **Why it fails** | **WP2 ladder — the lexical-dependence finding** |
| Metric critique | WP1 §4 + WP3 chance-level analysis |
| Confounds | WP4 — spec provenance, extraction defect |
| Every single-version method fails | WP3 baseline table |
| **The signal is there — it's the formulation** | **WP5 contrastive, 84.4%** |

The claim that survives review, in order:

1. Every formulation that examines one version at a time is at or below chance —
   the method (16.0%), direct prompting (6.9%), a static analyser (2.8%) — while
   PFA's chance level is 25% (WP3).
2. A perfect reconstruction does not help: the genuine patched function, merely
   renamed, scores 14.6% against the method's 16.0% (WP2 L1≈L3). Generator
   capability is not the constraint.
3. The judge's comparison ability is largely lexical: renaming locals costs 25
   points of PFA and 0.21 AUC, with a 34.6%-vs-6.8% internal control (WP2 L0→L1).
4. But the information *is* in the data and the model *can* extract it — 84.4%,
   p < 1e-36, artefact-checked — when both versions are shown and the question is
   narrowed (WP5). So the failure is in the task formulation.
5. Two confounds compound it: the specifications are systematically derived from
   the vulnerable version (p = 2.9×10⁻⁶), and 28.3% of vulnerable snippets are
   mis-extracted (WP4).

That is a stronger paper than the pure null, and every number in it is measured
on one corpus with one model at zero marginal cost.

## 8b. If you want to push further

Ranked by expected value, all runnable locally and free:

1. **WP4(b), already scripted, not yet run.** Regenerate specs from the fixed
   side and re-run the method. If the score gap's sign flips, the paper can claim
   that *the provenance of the specification sets the direction of the detector's
   bias* — a transferable design constraint on the whole method family. If it does
   not flip, provenance is exonerated. Both outcomes are publishable; this is the
   best remaining experiment per GPU-hour.
2. **Move the contrastive framing to a single-version detector.** The obvious
   bridge: use the reconstruction as the second version, but ask the *contrastive*
   question rather than the 5-way one. The `generated` mode already shows the
   reconstruction adds nothing as passive context — the open question is whether
   it works as the compared side. That would be a genuinely deployable method and
   is one run away.
3. **Re-score everything with a threshold on a decoupled score.** WP1 shows the
   category explains 57.9% of the score's entropy; a rubric that scores similarity
   independently of the category would make ROC-AUC a real second measurement.
4. **Fix the extraction defect** and re-derive the corpus. 28.3% of vulnerable
   snippets are malformed; the clean-extraction rate is well below the ~49%
   currently claimed.
5. **Variance**: 3 seeds on the headline arm. Currently a single run with no
   run-to-run estimate (threat #4 in the write-up).

## 9. Reproduction

```bash
bash scripts/serve_qwen.sh
python3 experiments/2026-08-15_statistical-rebuild/run.py            # no GPU
python3 experiments/2026-08-15_oracle-ladder/run.py --rungs L0 L1 L2
python3 experiments/2026-08-15_oracle-ladder/report.py
python3 experiments/2026-08-16_baselines/run.py --arms B1 B1s B2
python3 experiments/2026-08-16_baselines/report.py
python3 experiments/2026-08-17_spec-provenance/analyze.py            # no GPU
python3 experiments/2026-08-18_rescue-arms/run_contrastive.py --mode oracle
python3 experiments/2026-08-18_rescue-arms/run_contrastive.py --mode generated
```

Isolation gate: `git status --porcelain` must show changes only under
`experiments/`.
