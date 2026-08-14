# Can an LLM find vulnerabilities by reimplementing code from its documentation?

### A corpus-scale negative result, and a measurement of what the formulation costs

> **Draft for submission.** Assembled from `experiments/RESEARCH_LOG.md`, which
> holds the full chronological record including motives, failed hypotheses and
> corrections. Chapter references point there. Section 6 is pending chapter 12.

---

## 1. The idea, and why it is attractive

Supervised vulnerability detection needs labelled vulnerable code, which is
scarce, noisy and quickly stale. This project tests an **unsupervised**
alternative that needs only documentation:

1. Take a function and its docstring.
2. Give an LLM **only the docstring** — never the code — and ask it to implement
   the function from scratch.
3. Give a second LLM the real code and the generated code, and ask how they
   differ behaviourally.
4. A security-relevant divergence between what the documentation describes and
   what the code does may indicate a vulnerability.

The appeal is that documentation is abundant where vulnerability labels are not,
and that the generated implementation acts as an independent, uncontaminated
reading of intent.

**Three constraints define the method**, and every experiment below either
respects them or is explicitly labelled as a diagnostic that does not:

- **Information isolation** — the Generator sees only `{language, docstring}`.
- **One reference at a time** — the Judge compares against a single version and
  is never told which, or that a vulnerability is involved.
- **No supervised signal** — the vulnerable/fixed pairing exists only in the
  evaluation harness.

## 2. Experimental setup

**Corpus.** 553 CVE fix commits, 792 function-level cases; 392 pass extraction
(~49%). 374 C, 18 C++; 320 CVEs across 66 repositories, 51% `torvalds/linux`.
Each case holds the pre-patch and post-patch version of one function plus a
structured docstring. Median fix touches **8 lines**; median function 45 lines.

**Models.** Two independent stacks: Claude Haiku (generator) + Sonnet (judge),
and Qwen3-32B-AWQ in both roles, served locally with grammar-constrained
decoding, fixed seed, temperature 0.2/0.0. Prompts are read from a single source
and digested (`prompt_sha`) into every result record, so prompt drift between
arms is detectable rather than assumed absent.

**Evaluation.** Because each case has both versions, the detector runs twice and
is scored on whether it treats them differently in the right direction.

## 3. The primary metric is not what it appears to be

The project pre-registered **Paired Flag Accuracy** (PFA) — the vulnerable side
flagged a security concern and the fixed side not — with go/no-go bands of ≥80%
GO, 60–80% expand, <60% NO-GO.

**PFA's chance level is 25%, not 0%.** A detector flagging each side
independently with probability *p* scores `p(1−p)`, maximised at p = 0.5. A
measured coin flip reaches **31.4%**. Two consequences:

- The pre-registered bands were calibrated as though chance were zero. Against a
  true chance level of 25%, the 60% floor sits near the midpoint between chance
  and perfect.
- PFA rewards **asymmetry between the two calls**, not accuracy: `always flag`
  and `never flag` both score 0%, because a constant predictor supplies no
  asymmetry. A metric that looks like accuracy does not behave like one.

Two further measurement defects, both material:

- **Ties.** 43.1% of cases tie on the judge's score, and the secondary metric
  counted ties as failures. The tie-corrected figure is 46.3% (n=203), not 26.3%.
- **Score/category redundancy.** The rubric binds score ranges to categories; the
  category explains 57.9% of the score's entropy, and 92.3% of scored mass sits
  in {2,3,4,5}. ROC-AUC is therefore *not* independent evidence from PFA.

Later analyses use **directional accuracy** — does the vulnerable reference score
higher, given the same candidate? — where chance is exactly 50% and ties are
reported as coverage rather than folded into the numerator. *(ch. 5, 7)*

## 4. Main result: the method does not work

| Metric | Value | 95% CI (CVE-clustered) |
|---|---|---|
| Paired Flag Accuracy | **16.0%** (57/357) | [12.2%, 20.0%] |
| Directional accuracy | **43.5%** | [36.9%, 50.0%] |
| ROC-AUC | 0.475 | [0.442, 0.509] |

Outcome shape: flags vulnerable only 15.1%; flags **fixed** only 17.4%; flags
both 23.0%; flags neither 44.5%. **The detector is wrong-way-round more often
than right.**

CIs resample whole CVEs, not cases — 357 cases span only 302 CVEs and half come
from one repository, so case-level independence does not hold.

**A permutation null replaces an unsound argument.** An earlier draft argued the
method performs below chance by multiplying the two marginal flag rates
(0.412 × 0.560 = 23.1%) and noting 16.0% falls short — but that multiplication is
valid only under the independence the argument itself denies. A permutation null
that swaps both verdicts within a case preserves the correlation and centres at
**17.4% [14.3%, 20.4%]**; the observed 16.0% sits inside it (p = 0.21).

The defensible statement is assumption-free and stronger: **paired flag accuracy
is statistically indistinguishable from a null in which the reference shown to
the judge has no effect on its verdict.** *(ch. 4, 5)*

## 5. Why it fails

### 5.1 Not the model, the context, or the reconstruction

Four independent levers, each measured rather than argued:

| Lever | Result |
|---|---|
| Stronger generator (Haiku → Qwen3-32B in both roles) | 15.4% → 16.0% — no change |
| More context (real source file, target body masked) | 15.4% → 15.4% — no change |
| **Perfect reconstruction** (the genuine patched function) | **14.6%** — no change |
| Ensembling (K=5 independent reconstructions) | 50.3% directional, p = 1.000 |

The third row is the decisive one. Replacing the generated candidate with the
**real patched function, with local variables renamed**, is the ceiling for any
generator that will ever exist. It scores 14.6% against the method's 16.0%. *(ch.
3, 4, 6, 11)*

### 5.2 The judge compares text, not behaviour

An oracle ladder holds the judge, rubric and prompt fixed and varies only what
plays the role of the candidate:

| Rung | Candidate | PFA | ROC-AUC | flags patched code |
|---|---|---|---|---|
| L0 | patched function, verbatim | 39.7% | 0.887 | **0.6%** |
| L1 | patched function, **renamed** | **14.6%** | 0.674 | 0.3% |
| L3 | generated from spec | 16.0% | 0.475 | 44.0% |

L0 and L1 are semantically identical. Renaming local variables and stripping
comments — changes the rubric explicitly calls irrelevant (*"Different variable
names … are **not** behavioral differences"*) — costs **25 points of PFA and 0.21
AUC**, about 52% of the entire fall from oracle to method.

The internal control removes any doubt: within L1, cases with no renameable
locals score **34.6%** (n=26); cases with five or more renames score **6.8%**
(n=219).

**The LLM judge's apparent ability to compare two implementations behaviourally
is, on this corpus, largely lexical.** This is the paper's most transferable
finding: it constrains any LLM-as-judge code-comparison design, not just this
method.

Two corollaries: the 44% false-positive rate on *patched* code is manufactured
entirely by the reconstruction step (0.6% at L0), and PFA discards signal the
same data contain (L0 gives AUC 0.887 but PFA 39.7%, because the judge saw the
difference and declined to call it a security concern). *(ch. 6)*

### 5.3 The specifications describe the vulnerable code

Counting identifiers unique to one side of the fix against the docstring:

| | mentions | cases leaning this way |
|---|---|---|
| vulnerable-only | **470** | 94 |
| fixed-only | **127** | 41 |

**3.7× asymmetry; sign test p = 2.9×10⁻⁶.** The dataset's `scope` entries carry
line numbers into the pre-patch file, confirming the mechanism.

This survives an earlier leakage audit that removed 153 docstrings *stating* the
fix — that audit could not remove the fact that the specification was written by
reading the vulnerable function. It predicts both otherwise-unexplained
anomalies: ROC-AUC below 0.5, and a mean score gap favouring the vulnerable side.

**This is not only a dataset artefact.** In deployment a project's docstring is
written alongside the code it documents — the vulnerable version, right up until
the patch lands. Any spec-reconstruction detector inherits this bias wherever the
specification is not authored independently of the implementation. *(ch. 8)*

### 5.4 The failure is over-determined

Three independently sufficient causes: the metric discards signal, the judge is
lexically dependent, and reconstruction destroys what survives. No single fix
addresses all three — which is why four rescue levers each failed independently.

## 6. Four attempts to rescue the method, all within the premise

Section 7 shows the signal exists. So we reformulated the method four times,
keeping all three constraints of §1 intact each time. Each attempt targets a
mechanism established above rather than guessing.

| # | Reformulation | What it targets | Directional accuracy |
|---|---|---|---|
| 0 | published method (5-way taxonomy) | — | 43.5% (below chance) |
| 1 | narrow guard-omission question, K=1 | the holistic comparison (§5.2) | 48.8% |
| 2 | + five-sample consensus, K=5 | reconstruction noise (Finding 2) | 50.3% |
| 3 | + defensive generator & per-claim verification | the spec's information deficit | 57.1% → **53.3%** |

**Attempt 1 — ask a narrower question.** Replace the five-way taxonomy with one
predicate: does one side omit a defensive step the other performs? Rate each side
independently. Directional accuracy 48.8% (p = 0.82). This *removes the
anti-signal* — the published method's 43.5% points the wrong way, consistent with
the provenance confound of §5.3 — **without creating signal**.

**Attempt 2 — ensemble the reconstruction.** The published method draws one
sample, the maximum-noise configuration of its own idea. Draw five independent
reconstructions and count only defensive steps a majority agree on. Two
pre-registered tests; both null (50.3%, p = 1.000; 49.6%, p = 0.949).

In hindsight this could not have worked, and the reason is instructive:
**consensus reduces variance, not information.** All five samples are drawn from
the same specification, and §5.3 established that specification does not contain
the property the fix restores. We reached for the standard variance-reduction
tool without first asking whether the deficit was variance or information.

**Attempt 3 — supply what the specification lacks.** The published generator
prompt instructs the model to implement *"exactly as specified"*. Given that
specifications are derived from the vulnerable version (§5.3), that instruction
optimises for reproducing the bug. So we asked instead for a *defensively
hardened* implementation plus an explicit checklist of the guards it performs,
and had the judge verify **each claim individually** against one reference —
converting open-ended comparison, which §5.2 shows is performed lexically, into
per-claim verification where irrelevant differences are never asked about.

This is the only attempt that passed its pre-registered test: **57.1%,
p = 0.045**, with the predicted dissociation (anticipatable fixes 60.4%,
p = 0.036; domain-specific control 53.5%, p = 0.55).

**It does not replicate.** A second run at a different seed, identical in every
other respect, gives **53.3%, CI [46.9%, 59.9%], p = 0.351** — and the
dissociation *reverses*, the control stratum (54.0%) outscoring the stratum the
mechanism predicts should work (52.8%).

Pooling both runs (a post-hoc decision, disclosed as such) gives 55.2% with a
binomial p of 0.035 — but a CVE-clustered 95% CI of **[49.9%, 60.5%]**, which
includes chance. The binomial test assumes the case-level independence this
corpus does not have. *This is the same error §3 identifies in the original
analysis, reappearing in our own; we report it because catching it in ourselves
is part of the result.*

What survives is a small, consistent, sub-resolution effect: the per-case score
delta is positive in both runs (+0.216, +0.296 on a scale whose mean is ~7.7).
**There may be a real effect of order 55% directional accuracy. It is below what
this corpus can establish, and it is not a working detector.**

**Conclusion.** Four reformulations and four generator-side levers have now been
measured. None yields a reliable detector. The bounded negative of §4–5 stands,
with the strongest available evidence that it is not for want of trying.

## 7. The signal exists — the formulation is what fails

Asking the **same model** the guard-omission question with **both** versions
present, order randomised, `neither` permitted as an abstention:

| Mode | decided | accuracy | 95% CI |
|---|---|---|---|
| both versions | 308/391 | **84.4%** | [80.1%, 88.4%] |

Exact binomial against 50%: **p < 1.1×10⁻³⁶**. Two known artefacts are ruled out:
accuracy is unchanged on the 28.3% of malformed extractions (83.7% vs 84.8%), and
is *highest* on equal-length pairs (89.0%) where line count carries no
information — the opposite of a length heuristic.

**This is not a deployable detector.** It requires both the pre- and post-patch
versions, which is exactly what a real detector does not have. It is a ceiling,
not a method.

But it settles the question the negative result must answer: the information
needed to separate the two versions **is present in this corpus**, and this model
**can extract it**. The method's 16.0% is therefore a property of the **task
formulation** — two independent judgements, a five-way taxonomy, a metric
requiring one specific category — not of the model, the corpus, or the difficulty
of the underlying problem.

**The gap between 84.4% and 16.0% is the quantified cost of the formulation.**
*(ch. 9)*

## 8. Baselines

Every arm scored with the identical paired metric on the identical cases:

| Arm | PFA | ROC-AUC |
|---|---|---|
| Coin flip | 31.4% | 0.489 |
| `longer side is vulnerable` (line counts only) | 21.4% | 0.536 |
| **Method** | **16.0%** | 0.475 |
| Direct prompt + spec | 7.2% | 0.526 |
| Direct prompt ("is this vulnerable?") | 6.9% | 0.514 |
| flawfinder 2.0.20 | 2.8% | 0.514 |

**Every single-version formulation is at or below chance.** Direct prompting —
the obvious thing a practitioner would try — is *worse* than the method and at
chance on AUC. The failure is not peculiar to spec reconstruction. *(ch. 7)*

## 9. Threats to validity

1. **Extraction quality.** 111/392 (28.3%) vulnerable snippets are
   brace-unbalanced — they over-run the target function — against 3/392 on the
   fixed side. All carry `extraction_status: "ok"`. Restricting to clean cases
   moves PFA 16.0% → 15.8%, so this does not explain the null, but it biases
   every length-correlated comparison and the ~49% clean rate is optimistic.
2. **Ground truth is commit-level.** A function is labelled vulnerable because
   the fix commit touched it, not because it was individually verified.
3. **Single seed per arm.** No run-to-run variance estimate.
4. **Quantisation.** Qwen3-32B served 4-bit AWQ, not fp16.
5. **The Claude arm's models are unpinned aliases**, so its numbers are not
   exactly reproducible.
6. **Spec provenance is measured lexically** and cannot detect paraphrase, so
   3.7× is a lower bound. The causal test — regenerating specs from the fixed
   side — is scripted but unrun, and is a *diagnostic*: doing so would manufacture
   the leakage the earlier audit removed, and must never be reported as a method
   improvement.
7. **Two prompts change at once** in chapter 12, so a positive result there could
   not be attributed to one without a follow-up ablation.

## 10. What we would do next

1. **Fix the extraction pipeline** and re-derive the corpus.
2. **Semantic spec-sufficiency labels**, to replace a lexical proxy that failed.
3. **Seed variance** across all arms.
4. `adds_bounds_or_range_check` was the one fix category above chance (59.7%,
   n=62, uncorrected) — a lead for future work, explicitly not a result.

## Appendix A — On method

Four hypotheses in this project were predicted, tested, and **rejected**. Each
would have entered the paper as a finding had it been reported from the data that
suggested it.

| Hypothesis | Discovery | Confirmation |
|---|---|---|
| Lexical spec-sufficiency stratifies results | motivated by 47.7% zero-coverage | no gradient in either arm |
| Anticipatable-fix dissociation | 67.9% at n=28, p=0.087 | **54.7%** at n=86, p=0.45 |
| Net-exposure decision rule | 56.7%, p=0.030 (K=1) | **49.6%, p=0.949** (K=5) |
| Defensive claims (§6, attempt 3) | **57.1%, p=0.045** (seed 1234) | **53.3%, p=0.351** (seed 5678) |

The last two are the clearest. Net exposure was found by searching five decision
rules on one dataset; pre-registering it for an independent dataset is the only
reason it is not reported here as a finding. Defensive claims is stronger still:
it *passed* a genuinely pre-registered primary test at p = 0.045, and evaporated
on a seed change.

Three warning signs were recorded **before** that replication ran, and all three
proved well-founded: omission counts identical across sides (1.50 vs 1.49), an
implausible 37.6% `omits` rate against only 11.1% `not_applicable`, and a flat
coverage–accuracy curve. Writing them down in advance is what makes the failed
replication interpretable rather than merely disappointing.

**Two lessons we would carry to any similar study.** First, a marginal p-value on
a single run of an LLM pipeline is not evidence: two such results in this project
went from p = 0.030 and p = 0.045 to p = 0.949 and p = 0.351 under nothing but a
seed change. Second, binomial tests on clustered corpora overstate significance —
an error we identify in the original analysis (§3) and then reproduce in our own
pooled estimate (§6). Both are cheap to guard against and expensive to miss.

## Appendix B — Reproducibility

Every experiment is additive: `scripts/`, `cases/`, `results/`, `reports/` and
the agent definitions are unmodified throughout, and `prompt_sha` still resolves
to `1de29ae28c7d` on every arm meant to reuse the published rubric. Each arm
records its own prompt digest, seed, served model and arm label in every result
record. Reproduction commands are in each arm's `README.md`.
