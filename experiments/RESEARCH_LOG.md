# Research Log — Unsupervised vulnerability detection by specification reconstruction

**Purpose of this document.** One running narrative of the whole investigation:
every experiment, why we thought it was worth doing, what we did, what came back,
what we concluded, and what was wrong with it. Written as it happens so that the
paper can be assembled from it rather than reconstructed from memory afterwards.

**How to use it.** Chapters are chronological. Each experiment chapter has the
same shape:

> **Question** · **Why we expected it to work** · **What we did** · **Results** ·
> **Findings** · **Conclusions** · **Weaknesses** · **Pros and cons** ·
> **What it changed in our beliefs**

A running **State of belief** section after each chapter tracks what we think is
true at that point, so the paper can show the reasoning moving rather than
presenting conclusions fully formed.

**Conventions.** Negative results and failed hypotheses are recorded in full,
including ones that looked positive at an interim checkpoint. Where an earlier
claim in this log is later overturned, the original stays and the correction is
appended — the paper needs the trajectory, not a cleaned-up version of it.

**Last updated**: 2026-08-14, during the consensus (K=5) run.

---

## Table of contents

| # | Chapter | Outcome |
|---|---|---|
| 0 | The premise and the dataset | — |
| 1 | The original method and the 27-case pilot | Null, confounded |
| 2 | Docstring-leakage audit | Confound removed |
| 3 | Wider-context ablation | Negative |
| 4 | Corpus-scale local arm (Qwen3-32B, n=391) | Null, solid |
| 5 | Statistical rebuild | 3 corrections to ch. 4 |
| 6 | The oracle ladder | **Key mechanism finding** |
| 7 | Baselines | Every single-version method at chance |
| 8 | Specification provenance + extraction defect | 2 new confounds |
| 9 | Contrastive judge (both versions) | **84.4% — signal exists** |
| 10 | Guard contrast, K=1 | Null |
| 11 | Consensus guard, K=5 | *in flight* |

---

# Chapter 0 — The premise and the dataset

## The idea being tested

From the original project brief (`problem-descirption.txt`):

1. For each function we have the code and its documentation.
2. Give **only** the documentation to an LLM — never the code.
3. Ask it to write an implementation from scratch.
4. Give the real code and the generated code to a second LLM acting as judge.
5. The judge rates behavioural/semantic similarity.
6. A significant mismatch may indicate a bug, a spec deviation, or a
   vulnerability.

The appeal is that it is **unsupervised**: no labelled vulnerability data, no
training. It needs only documentation, which most real codebases already have.

## The three constraints that define the method

These are what make it *this* method rather than some other one. Every experiment
in this log either respects them or is explicitly labelled as a diagnostic that
does not:

1. **Information isolation** — the Generator sees only `{language, docstring}`.
   Never code, CVE id, repository, commit message.
2. **One reference at a time** — the Judge compares the candidate against a
   single version and is never told which version it is, or that a vulnerability
   is involved.
3. **No supervised signal** — the vulnerable/fixed pairing exists only in the
   evaluation harness. The detector never sees a label.

## The dataset

`D.zip`: 553 CVE fix commits, 792 function-level cases, extracted by
`scripts/extract_cases.py` into `cases/*.json`. Each case carries a vulnerable
(pre-patch) and fixed (post-patch) version of the same function plus a structured
docstring (Summary / Parameters / Returns / Logic).

- 392 of 792 carry `extraction_status: "ok"` (~49% clean rate)
- 374 C, 18 C++; 320 distinct CVEs, 66 repositories
- 51% from `torvalds/linux`, then chromium (44), ImageMagick (35)
- Median fix touches **8 changed lines** (p25 = 4); median function 45 lines
- 199/392 fixes add a conditional or assertion

## The evaluation harness

Because each case has both versions, the detector can be run twice per case and
scored on whether it treats the two differently in the right direction.

- **Paired Flag Accuracy (PFA)** — the pre-registered primary metric: the
  vulnerable side is categorised `security_vulnerability_concern` and the fixed
  side is not.
- Pre-registered go/no-go bands: ≥80% GO, 60–80% expand, <60% NO-GO.

> **Recorded here because it matters later (ch. 7):** these bands were set as
> though chance were 0%. It is 25%. Nobody noticed until we measured it.

---

# Chapter 1 — The original method and the 27-case pilot

**Directory**: `.claude/agents/`, `results/pilot/`, `PILOT_INSIGHTS.md`

## What we did

Generator = Claude Haiku (cheapest adequate tier), Judge = Claude Sonnet, both
with zero tools and separate contexts. The judge returns `score` (1–10),
`category` (5-way), `security_relevant`, `confidence`, `rationale`. 27 pilot
cases.

## Results

PFA ≈ 9% on the 15 cases that completed before a usage limit stopped the run;
generation-failure rate 27%; ROC-AUC 0.52.

## Findings

Two, recorded in `PILOT_INSIGHTS.md`:

- **Finding 1 — an extraction bug.** All four `degenerate_generation` cases were
  the judge correctly calling incoherent code incoherent: the *fixed-side*
  extractor had landed on the wrong function or a nested block. The metrics were
  partly measuring the extractor.
- **Finding 2 — the "baseline gap".** In 8 of 11 scored cases the judge assigned
  the *same* category to both sides. The gap between a from-spec reconstruction
  and either real version swamped the much smaller gap between the two real
  versions.

## Conclusions at the time

Don't apply the go/no-go bands yet. Fix the extraction bug; treat Finding 2 as a
modelling choice to test (escalate the Generator) rather than a bug.

## Weaknesses

n = 15, a single arm, an unpinned model alias, and a metric whose chance level
was never established.

## What it changed in our beliefs

Finding 2 became the organising problem for everything that followed. In
hindsight (ch. 6) it was the right diagnosis of the wrong half of the pipeline.

---

# Chapter 2 — Docstring-leakage audit

**Directory**: `reports/docstring_audit/`, `scripts/audit_docstrings_llm_openai.py`

## Question

Do some docstrings state the fix, letting the Generator "solve" the case from the
spec text alone?

## Why we expected it to matter

If the spec says "validates the length before copying", a generator will write
that check, and detection becomes trivial for the wrong reason — the label has
leaked into the input.

## What we did

LLM audit of all 392 `ok` cases into
`confirmed_leak` / `not_a_leak` / `ambiguous`, with neutral rewrites spliced back
into `cases/*.json`.

## Results

**153 confirmed leaks / 213 clean / 26 ambiguous.** 152 rewrites applied.

## Findings

A large minority of specs did leak. After correction PFA stayed ≈15.4% — so
leakage was *not* what was propping the method up, and its removal did not hurt.

## Weaknesses

- Rewrites were applied **in place** to `cases/*.json`, so the pre-audit corpus
  is no longer directly recoverable.
- The audit removed docstrings that *state* the fix. It could not remove a
  subtler and more pervasive problem that we only found much later (ch. 8): the
  specs were **written from the vulnerable code in the first place**.

## What it changed in our beliefs

Ruled out the most obvious confound, and correctly so. Created a false sense that
the specification side was now clean.

---

# Chapter 3 — Wider-context ablation

**Directory**: `results/ablation_{baseline,context}/`, `reports/ablation_report.md`

## Question

Does giving the Generator the real source file — with the target function's body
masked — reduce the baseline gap?

## Why we expected it to work

Finding 2 says the reconstruction differs from both references because it invents
its own types, helpers and error conventions. Show it the real ones and those
differences should vanish, leaving the CVE difference visible.

## Results

| Metric | docstring only | + masked file context |
|---|---|---|
| PFA | 15.4% (2/13) | 15.4% (2/13) |
| Pairwise ranking | 38.5% | 30.8% |

## Findings

No help, slightly negative. And a mechanism worth keeping: masking a function's
*body* does not mask the file's *idiom*. In `C_761__0` the context arm copied the
CVE's vulnerable one-liner verbatim from three unmasked sibling accessors using
the same buggy pattern — turning a baseline-arm hit into a context-arm miss.
`C_623__0` shows the mirror, where imitating a safe sibling helped.

## Conclusions

More context is not the answer, and it introduces a new failure mode: the
surrounding file can teach the generator the vulnerable idiom.

## Weaknesses

n = 13. Cannot separate "no effect" from "underpowered".

## What it changed in our beliefs

Closed off lever 2 of 3 (more context). Left lever 1 (better model) and lever 3
(change the task).

---

# Chapter 4 — Corpus-scale local arm (Qwen3-32B, n=391)

**Directory**: `results/qwen_full/`, `experiments/2026-08-14_qwen3-32b-local-arm.md`

## Question

Two at once: does the method work at corpus scale, and is model capability the
bottleneck?

## Why we expected it to be informative

The 15.4% figure rested on 13 scored cases — too few to separate "the method
fails" from "the sample was unlucky". Running a 32B model in **both** roles tests
the capability lever directly, and running locally makes the full corpus free.

## What we did

vLLM + Qwen3-32B-AWQ on one RTX 4090. Prompts read directly from
`.claude/agents/*.md` so the two arms share prompt text exactly
(`prompt_sha = 1de29ae28c7d`). Grammar-constrained JSON. 391 cases, 1173 calls,
16 minutes, 0 failures.

## Results

| Metric | Value | 95% CI |
|---|---|---|
| **Paired Flag Accuracy** | **16.0%** (57/357) | [12.5%, 20.1%] |
| Pairwise ranking | 26.3% | — |
| ROC-AUC | **0.475** | — |
| Generation-failure rate | 8.7% | — |

Outcome distribution: flags vulnerable only 15.1%; flags **fixed** only 17.4%;
flags both 23.0%; flags neither 44.5%.

## Findings

1. **The pilot number was not a small-sample artefact** — 27× the sample, same
   answer.
2. **The detector is wrong-way-round more often than right** (68 vs 59).
3. **Model capability is not the explanation.** A 32B model in both roles
   reproduced Haiku+Sonnet. Two very different stacks land in the same place.
4. **The two arms agree on aggregate but not per case** — Cohen's κ = 0.091,
   zero overlap in detected cases. Consistent with detections being noise.
5. **Generation failure was mismeasured**: 8.7% pooled decomposes into 6.9%
   reference-side extraction artefacts, 1.0% harness truncation, and **0.8%**
   genuine model failure.

## Conclusions at the time

NO-GO at corpus scale. Levers 1 and 2 (better model, more context) both measured
and negative. The remaining lever is the task formulation itself.

## Weaknesses (as stated in that write-up)

Both roles swapped simultaneously; matched subset underpowered (n=13); Claude arm
uses unpinned aliases; single seed; commit-level ground truth; ~6.9% corrupt
references; 4-bit quantisation.

## What it changed in our beliefs

Made the null solid and correctly redirected attention from the models to the
task. **Three of its statistical claims turned out to be wrong** — see ch. 5.

---

# Chapter 5 — Statistical rebuild

**Directory**: `experiments/2026-08-15_statistical-rebuild/` · no inference

## Question

Do chapter 4's numbers survive proper statistics?

## Why we did it

The corpus is clustered (357 cases, 302 CVEs, 51% one repo) but the CIs are
binomial; the "below chance" argument multiplies marginals; and 43% of cases tie
on a metric that scores ties as failures. Before building anything new on this
foundation, check the foundation.

## Results and findings

**(a) The "below chance" claim does not survive.** §4.3(c) multiplies the two
marginal flag rates (0.412 × 0.560 = 23.1%) and infers positive correlation from
the shortfall — but the multiplication is valid only under the independence it
denies. A permutation null that swaps both verdicts within a case *preserves* the
correlation and centres at **17.4% [14.3%, 20.4%]**. Observed 16.0% sits inside
it, p = 0.21.

> Replacement claim, stronger and assumption-free: *PFA is statistically
> indistinguishable from a null in which the reference shown to the judge has no
> effect on its verdict.*

**(b) Ties.** 43.1% of scored cases tie. Tie-corrected 2AFC = **46.3%** (n=203),
CI [39.2%, 53.2%]. The published 26.3% is not comparable to a 50% line.

**(c) ROC-AUC is not independent evidence.** The rubric binds score ranges to
categories; the category explains **57.9%** of the score's entropy, and 92.3% of
scored mass sits in {2,3,4,5} with a gap where 6–8 should be. §4.3(a)/(b)/(c) is
one demonstration seen three ways.

**(d) Clustered CIs**: PFA [12.2%, 20.0%], AUC [0.442, 0.509].

**(e) No stratum rescues it.** PFA 10.3–20.6% across repos, 14.1–18.2% across
fix-size quartiles; every AUC within [0.445, 0.507].

## Conclusions

The null is real and if anything better supported — but three of the arguments
used to support it were unsound and would have been caught in review.

## Pros and cons

**Pro**: free, and it protects everything downstream. **Con**: purely corrective;
produces no new capability.

## What it changed in our beliefs

Taught us the metric itself was suspect — which set up ch. 7.

---

# Chapter 6 — The oracle ladder

**Directory**: `experiments/2026-08-15_oracle-ladder/` · 3 × 389 cases

## Question

*Where* in the pipeline is the signal lost?

## Why we expected it to be decisive

The obvious rebuttal to the null is "use a better generator". We could not afford
a frontier arm, and testing one more model would not settle it anyway. So instead
of improving the generator, **replace it with an oracle**: hold judge, rubric and
`prompt_sha` fixed and vary only what plays the role of the candidate. If the
judge succeeds when handed the true pair, no better judge can help; if a perfect
candidate does not help, no better generator can help. This bounds both halves
rather than sampling the model space.

## What we did

| Rung | Candidate |
|---|---|
| L0 | the fixed snippet, verbatim |
| L1 | the fixed snippet, locals renamed + comments stripped |
| L2 | the fixed snippet of a different, random case |
| L3 | the generated candidate (= the published run) |

## Results

| Rung | n scored | PFA | 95% CI | ROC-AUC | flags vuln | flags fixed | degenerate |
|---|---|---|---|---|---|---|---|
| L0 | 360 | 39.7% | [34.4%, 45.2%] | 0.887 | 40.3% | **0.6%** | 7.7% |
| L1 | 364 | **14.6%** | [10.9%, 18.6%] | 0.674 | 14.6% | 0.3% | 6.7% |
| L2 | 1 | — | — | — | — | — | **99.7%** |
| L3 | 357 | 16.0% | [12.3%, 20.2%] | 0.475 | 41.2% | 44.0% | 8.7% |

## Findings

**1. The judge depends on lexical overlap, contradicting its own rubric.**
Renaming locals and stripping comments — changes the rubric explicitly calls
irrelevant (*"Different variable names … are not behavioral differences"*) —
costs **25 points of PFA and 0.21 AUC**. Semantics are identical across L0 and
L1. ~52% of the entire fall from oracle to method happens at this step.

Internal control within L1:

| L1 subset | n | PFA |
|---|---|---|
| 0 identifiers renamed (reformat only) | 26 | **34.6%** |
| 5+ identifiers renamed | 219 | **6.8%** |

**2. A perfect generator would not have moved the primary metric.** L1 is the
genuine patched function — the ceiling for any generator that will ever exist —
and scores 14.6% against the method's 16.0%.

**3. The 44% false-positive rate on patched code is an artefact of
reconstruction.** The judge flags the patched reference on 0.6% of L0 and 0.3% of
L1 cases, against 44.0% at L3.

**4. PFA discards signal the same data contain.** At L0: AUC 0.887, PFA 39.7%. Of
the 215 L0 cases PFA calls misses, the judge said `functional_mismatch` (106),
`equivalent` (81), `quality_bug` (28) — it saw the difference and declined to
call it a security concern.

**5. L2 is a validity check and it passes.** Unrelated code → `degenerate` on
389/390. The judge is not indiscriminately pattern-matching. (Its PFA is computed
on n=1 and is meaningless — do not quote it.)

## Conclusions

The failure is **over-determined**: the metric discards signal, the judge is
lexically dependent, and reconstruction destroys what survives. No single fix
addresses all three — which is why better model, more context and now perfect
reconstruction each failed independently.

## Weaknesses

- At L0 the fixed-side comparison is byte-identical, so `equivalent` is trivially
  available and 0.6% is an optimistic floor. L0 must be read with L1, never alone.
- L1's renaming is deliberately conservative (locals and parameters only; macros,
  called functions and struct fields untouched), so it *under*-states lexical
  dependence if anything.
- 42/392 cases have no renameable locals, so L1 is a weaker perturbation there —
  which is exactly what the internal control exploits.

## Pros and cons

**Pro**: bounds both halves of the pipeline without buying frontier inference;
turns "we tried another model" into a structural argument. **Con**: an oracle
candidate is not a reachable operating point, so the ladder describes limits
rather than offering a method.

## Corrections made during this chapter

An intermediate reading — "the judge is fine, reconstruction is what fails" —
was based on L0 alone and **was wrong**. L1 overturned it. Also: L1 ≈ L3 on PFA
but *not* on AUC (0.674 vs 0.475), so reconstruction quality does matter to a
ranking metric. Correct phrasing is "irrelevant to the metric as pre-registered",
not "irrelevant".

## State of belief after ch. 6

- The method fails, at corpus scale, robustly. ✔ established
- Not because the generator is weak. ✔ established (L1)
- Not because the judge is weak in principle. ✔ (L0 AUC 0.887)
- Partly because the judge compares text, not behaviour. ✔ new
- Partly because the primary metric throws away signal. ✔ new

---

# Chapter 7 — Baselines

**Directory**: `experiments/2026-08-16_baselines/` · 2 × 392 model cases + CPU

## Question

Do the obvious alternatives do any better on the same cases?

## Why we did it

A negative result about a method is only worth reading if the alternatives are
measured with the same yardstick. And the paper had no answer to *"why not just
ask the model?"*

## Results

| Arm | PFA | 95% CI | ROC-AUC | flag rate v/f |
|---|---|---|---|---|
| Coin flip | **31.4%** | [27.0%, 36.0%] | 0.489 | 49.2% / 42.6% |
| `longer side is vulnerable` | 21.4% | [16.7%, 26.6%] | 0.536 | 21.4% / 4.3% |
| **Method** | **16.0%** | [12.3%, 20.2%] | 0.475 | 41.2% / 44.0% |
| Direct prompt + spec | 7.2% | [4.7%, 10.0%] | 0.526 | 10.5% / 7.4% |
| Direct prompt | 6.9% | [4.5%, 9.5%] | 0.514 | 10.2% / 7.4% |
| flawfinder 2.0.20 | 2.8% | [1.0%, 4.9%] | 0.514 | 18.4% / 15.8% |
| always / never flag | 0.0% | — | 0.500 | — |

## Findings

**1. PFA's chance level is 25%, not 0%.** A detector flagging each side
independently with probability *p* scores `p(1−p)`, maximised at p = 0.5. The
measured coin flip: 31.4%. **The method is below chance** — for this reason, not
chapter 4's. And the pre-registered 60%/80% bands were calibrated as though
chance were zero.

**2. PFA rewards asymmetry, not accuracy.** `always flag` and `never flag` both
score 0% — not because they are worse than a coin flip, but because a constant
predictor supplies no asymmetry between the two calls.

**3. Direct prompting is *worse* than the method** (6.9% vs 16.0%) and both are
at chance on AUC. Asked "is this function vulnerable?" about one function, the
model says yes ~10% of the time and cannot tell the versions apart. Supplying the
spec barely helps (+0.3 PFA, +0.012 AUC).

**4. A length artefact in the unexpected direction.** 74.2% of pairs have
identical line counts; among those that differ the vulnerable side is longer
about five times in six. Partly the extraction defect of ch. 8.

## Conclusions

The method's failure is not peculiar to spec reconstruction. **Every
single-version formulation on this corpus is at or below chance.** That is a
stronger and more citable claim than "our idea didn't work".

## Weaknesses

- flawfinder sees bare functions with no headers, macros or types, so its rules
  mostly find nothing. Report it as *a static analyser applied to this corpus as
  extracted*, not as its general capability.
- The trivial predictors are analytic, not tuned; a fitted length model would
  score higher and is not tested.

## State of belief after ch. 7

The primary metric is actively misleading. Everything single-version is at
chance. The remaining question is whether the *information* is even present.

---

# Chapter 8 — Specification provenance, and an extraction defect

**Directory**: `experiments/2026-08-17_spec-provenance/` · no inference

## Question

Where do these specifications come from — and is the corpus clean?

## Why we suspected something

Chapter 4 reports two anomalies it does not explain: ROC-AUC **below** 0.5, and a
mean score gap of −0.18 *favouring the vulnerable side*. Both are what you would
see if the reconstruction systematically resembled the vulnerable version. One
way that happens is if the spec describes the vulnerable version.

## What we did

For each case, count identifiers unique to one side of the fix that the docstring
mentions. A vulnerable-only identifier appearing in the spec is information the
spec could only have obtained from the vulnerable version.

## Results

| | mentions | cases leaning this way |
|---|---|---|
| vulnerable-only | **470** | 94 |
| fixed-only | **127** | 41 |

**3.7× asymmetry. Sign test over the 135 non-tied cases: p = 2.9×10⁻⁶.**

Corroboration: `D.zip`'s `scope` entries carry line numbers into
`vulnerable.<ext>` — the documentation was generated against the pre-patch file.

**A second, unrelated finding — an extraction defect.** `extract_cases.py` slices
the vulnerable snippet from the dataset's literal `scope.start`/`scope.end`
range, which over-runs the target function:

| Side | balanced | malformed |
|---|---|---|
| vulnerable | 281 | **111 (28.3%)** |
| fixed | 389 | 3 (0.8%) |

All carry `extraction_status: "ok"`. Example `C_102__0`: the vulnerable snippet
ends part-way into `shmem_show_options`, the function *after* the target. This is
the mirror of `PILOT_INSIGHTS.md` Finding 1 and was undocumented.

## Findings and conclusions

**The specs are derived from the vulnerable code, and this survives the ch. 2
audit.** That audit removed docstrings *stating* the fix; it could not remove the
fact that the spec was written by reading the pre-patch function. It predicts
both unexplained anomalies.

**This is not only a dataset artefact.** In deployment a project's docstring is
written alongside the code it documents — the vulnerable version, right up until
the patch lands. Any spec-reconstruction detector inherits this bias wherever the
spec is not authored independently of the implementation. That is a design
constraint on the whole method family, not a quirk of `D.zip`.

**The extraction defect does not explain the null**: PFA moves 16.0% → 15.8% on
cleanly extracted cases. It belongs in Threats and it biases length-correlated
comparisons.

## A hypothesis that failed, recorded in full

The natural companion claim — *the spec is silent about what the fix changed* —
has real support: 47.7% of cases mention **none** of the identifiers that differ
between versions, median coverage 4.3%. But **stratifying the results by that
proxy does not separate the strata**: L3 PFA runs 14.1% → 16.2% → 19.4% across
increasing coverage, and L0 shows no gradient at all. The lexical proxy is too
crude to carry the claim. It needs a semantic label to stand.

## Weaknesses

- The provenance measure is lexical and cannot detect a spec that paraphrases
  the vulnerable code without reusing identifiers, so it is a **lower bound**.
- Correlational. The causal test — regenerate specs from the *fixed* side and
  look for a sign flip — is scripted (`respec.py`) but **not yet run**.
- Note a trap: regenerating specs from the fixed code would *manufacture* the
  very leakage ch. 2 removed. It is a valid **confound diagnostic**, not a method
  improvement, and must never be reported as the latter.

---

# Chapter 9 — Contrastive judge (both versions)

**Directory**: `experiments/2026-08-18_rescue-arms/` · 2 × 391 cases

## Question

Is the information needed to separate the two versions present in this data at
all, and can this model extract it?

## Why we expected it to work

Chapter 5's permutation test says the reference barely enters the verdict. The
structural reason is that each judge call sees only *one* reference, so "is this
difference security-relevant?" is dominated by whatever the candidate differs
from in general. Showing both at once and narrowing the question to a single
predicate removes that confound and gives a clean 50% chance line.

## What we did

One call, both versions present, order randomised per case from a seeded hash of
the case id, one question: *does one side omit a defensive step the other
performs?* `neither` permitted and scored as an abstention.

Two modes: **oracle** (the two snippets only) and **generated** (the same, plus
the spec-reconstruction candidate as extra context).

## Results

| Mode | decided | accuracy | 95% CI | abstained |
|---|---|---|---|---|
| oracle | 308/391 | **84.4%** | [80.1%, 88.4%] | 21.2% |
| generated | 325/391 | 81.5% | [77.2%, 85.8%] | 16.9% |

Exact binomial against 50%: **p < 1.1×10⁻³⁶**.

## Artefact checks — both pass

| Check | Result | Reading |
|---|---|---|
| Extraction defect (28.3% malformed) | clean 84.8%, malformed 83.7% | no effect |
| Length | equal-length **89.0%**, unequal 66.7% | *opposite* of a length heuristic |
| Position | always-A would score 47.6% | order randomised per case |

Accuracy being **highest** on equal-length pairs — where line count carries zero
information — is the strongest single piece of evidence that this is semantic.

## Findings

**The information is present and the model can extract it.** Same weights, same
corpus, 84.4%. So the published method's 16.0% is a property of the **task
formulation** — two independent judgements, a 5-way taxonomy, a metric requiring
one specific category — not of the model, the corpus, or the difficulty of the
problem.

Supplying the reconstruction as passive context changes nothing (81.5% vs 84.4%),
corroborating ch. 6: the reconstruction is not where the value is.

## Weaknesses — and the hard limit

**This is not a deployable detector.** It requires *both* the pre- and post-patch
versions, which is exactly what a real detector does not have: at detection time
only one version exists. It violates constraint 2 of ch. 0. It is a **diagnostic
and a ceiling**, not a method, and presenting it as a working vulnerability
detector would be wrong.

Also: 21.2% abstention is not free — accuracy is quoted on the decided subset,
and the all-cases figure is 66.5%.

## Conclusions

The honest framing: **the gap between 84.4% (both versions, right question) and
16.0% (one version, wrong question) is the quantified cost of the formulation.**
This is what converts the paper from *"this does not work"* into *"this does not
work, and here is proof the failure is in the formulation rather than the data"*.

## State of belief after ch. 9

- Information present in the data: ✔ **yes**, decisively
- Model capable of using it: ✔ **yes**, 84.4%
- Failure located in: the **question we ask**, not the data or the model
- Therefore: a reformulated method that stays single-version is worth building

---

# Chapter 10 — Guard contrast, K=1

**Directory**: `experiments/2026-08-19_guard-contrast/` · 391 cases

## Question

Does the narrow guard-omission question work when the compared side is the
*reconstruction* rather than the real patched function — i.e. within the premise?

## Why we expected it to work

This is the direct bridge from ch. 9 back to a legal method. Chapter 9's question
works; chapter 6 says the judge's holistic 5-way comparison is the problem. So
keep the pipeline and change only the question. To isolate that change we reused
the **exact candidates** from `results/qwen_full/`, so the generation half is
byte-identical to the published arm.

Design details: the two implementations are presented as anonymous peers 1 and 2
in an order randomised per case (fixed *within* a case, so the two judge calls
differ only in the reference); each side is rated independently rather than
picking a winner; output is a continuous exposure score plus explicit lists of
the differing defensive steps.

## An intermediate design correction

The first version asked for a single `more_exposed_side` winner. It saturated:
the judge almost always named the **candidate**, because an LLM's from-spec
reconstruction genuinely *is* less defensive than real kernel code. Replaced with
independent per-side severities. Worth recording — the baseline gap reappears in
whatever form the question allows.

## Results

| stratum | n | decided | coverage | accuracy | 95% CI | p |
|---|---|---|---|---|---|---|
| all | 391 | 170 | 43% | **48.8%** | [41.4%, 56.3%] | 0.82 |
| anticipatable fix | 195 | 86 | 44% | 54.7% | [44.0%, 65.2%] | 0.45 |
| domain-specific | 196 | 84 | 43% | 42.9% | [32.6%, 53.7%] | 0.23 |

## A failed hypothesis, recorded in full

At an interim checkpoint (n=137) this arm showed exactly the dissociation we had
predicted from the mechanism: 67.9% on the anticipatable stratum (p=0.087) versus
50.0% on the rest. **It did not survive the full sample** — 67.9% → 54.7%, CI
comfortably including 50%.

The stratification was pre-specified in `experiments/common/cve_taxonomy.py`
(lexical, diff-only, no model involved) and the prediction written down in
`PRE_REGISTRATION.md` *before* the confirmatory run. That is what caught it. A
28-case subgroup that looked strong was sampling variation, and treating it as a
finding would have been wrong.

## Findings

**Single-candidate guard contrast does not work.** The mechanism is visible in
the distributions: the judge rates the reference's exposure at **0 in 63% of
vulnerable and 61% of fixed cases**, and mean exposure is 1.31 vs 1.37 — a −0.06
delta, slightly the wrong way. One reconstruction usually does not contain the
guard the vulnerable version lacks.

## A second hypothesis, generated here and deliberately not claimed

Searching the records for a better decision rule found **net exposure**
(reference minus the candidate's own): 56.7% at 71% coverage, p = 0.030. Five
rules were tried, so Bonferroni-corrected that is p ≈ 0.15. **Not a result.**

It is principled rather than arbitrary: when a reconstruction is weak, everything
compared against it looks defensively better, and that offset is common to both
judge calls, so differencing removes it. That also explains why the raw rule
fails. It was pre-registered as a secondary hypothesis for the K=5 arm, whose
data are independent of the data that suggested it.

## Pros and cons

**Pro**: fully within the premise; isolates the judge change perfectly by reusing
the published candidates; produces a continuous score with an honest 50% chance
line. **Con**: 56.5% tie rate, so coverage is only 43%; and the underlying
problem — one sample rarely contains the guard — is untouched by rewording.

## What it changed in our beliefs

Filled in the 2×2 that now drives everything:

| | published 5-way judge | narrow guard question |
|---|---|---|
| generated candidate | 16.0% PFA | 48.8% directional |
| **perfect candidate** | 14.6% PFA (L1) | **84.4%** (ch. 9) |

The bottom-right cell is ch. 9 restated: when the candidate *is* the patched
function, candidate-vs-vulnerable **is** fixed-vs-vulnerable. So under the right
question, going from a generated to a perfect candidate moves accuracy 48.8% →
84.4%. **Under the right question, reconstruction quality is the binding
constraint** — which is precisely what an ensemble should improve.

Note this does not contradict ch. 6's "a perfect generator would not have moved
PFA". Both are true: under the *wrong* question candidate quality is irrelevant;
under the *right* question it is everything. That contrast is itself a finding.

---

# Chapter 11 — Consensus guard, K=5 *(in flight)*

**Directory**: `experiments/2026-08-20_consensus-guard/`

## Question

If reconstruction quality is the binding constraint under the narrow question,
does an **ensemble** of independent reconstructions recover the signal?

## Why we expect it to work

The published method draws **one** sample. That is the maximum-noise
configuration of its own idea, and `PILOT_INSIGHTS.md` Finding 2 named the
consequence in the pilot without ever addressing it. Chapter 10 measured the
mechanism precisely: the judge rates reference exposure at 0 in ~62% of calls,
because one reconstruction is usually less defensive than real code.

A defensive step that **3 of 5 independent implementations** perform is a
consequence of the specification; a step only one performs is that sample's
idiosyncrasy. Consensus is exactly the filter the baseline gap has needed since
the pilot — and it is the first time the project has attacked Finding 2 at its
source rather than around it.

## What we are doing

- K = 5 independent samples per case from the **published, unmodified** generator
  prompt (`prompt_sha` still `1de29ae28c7d`), temperature 0.8, distinct seed per
  sample. Verified: 5 genuinely distinct implementations per case.
- All K candidates in **one** judge call per reference, so the judge applies the
  majority rule with the evidence in front of it and cost stays at 2 calls/case.
- The rubric requires a majority before a step counts, and rates **both**
  directions (`target_exposure` and a `consensus_exposure` control), so the
  pre-registered net-exposure rule can be computed.
- Premise intact: generator sees only the docstring; judge sees one reference at
  a time; no labels.

## Pre-registered before any records existed

`PRE_REGISTRATION.md` fixes: the strata, the primary metric (directional
accuracy, 50% chance, ties as coverage), **H1** (target exposure) and **H2** (net
exposure), the Bonferroni threshold p < 0.025 for two tests, and the
falsification conditions. All outcomes will be reported, with the unstratified
number always shown alongside any stratified one.

## Expected weaknesses regardless of outcome

- 5 candidates plus a reference is a long prompt; oversize cases degrade to fewer
  samples (minimum 2), recorded per case as `k_used`.
- K=5 costs 5× the generation of the published method — a real deployment cost
  that must be stated.
- Consensus can only supply steps that *ordinary practice* suggests. It cannot
  invent a domain-specific fix, so a ceiling well below ch. 9's 84.4% is expected
  even if it works.

## Results

391 of 392 cases judged; `C_1313__0` failed on prompt size (5 candidates plus a
reference exceeds the window; it is the same case the published run skipped).

| Arm | decided | coverage | accuracy | 95% CI | p |
|---|---|---|---|---|---|
| published method (5-way) | 230 | 58.8% | **43.5%** | [36.9%, 50.0%] | 0.056 |
| guard contrast, K=1 | 170 | 43.5% | **48.8%** | [41.4%, 56.1%] | 0.818 |
| **consensus guard, K=5** | 175 | 44.8% | **50.3%** | [42.7%, 57.7%] | **1.000** |

### The two pre-registered tests — both fail

| # | hypothesis | decided | accuracy | 95% CI | p | verdict |
|---|---|---|---|---|---|---|
| H1 | consensus exposure of the target | 175 | 50.3% | [42.7%, 57.7%] | 1.000 | **n.s.** |
| H2 | net exposure (target − consensus control) | 244 | 49.6% | [43.1%, 56.1%] | 0.949 | **n.s.** |

The pre-registered dissociation, on H1: anticipatable 55.9% [45.9%, 65.9%]
p = 0.30; domain-specific 43.9% [33.3%, 54.9%] p = 0.32. Direction as predicted,
significance absent, CIs overlapping heavily.

Coverage–accuracy trade-off is flat — demanding a larger margin buys no accuracy
(margin ≥2: 52.0%; ≥3: 50.6%; ≥4: 50.8%; ≥5: 47.1%). There is no confident
subset. By fix category the only bucket above chance by any margin is
`adds_bounds_or_range_check` at 59.7% (n=62), which is one bucket out of seven
and not corrected for multiplicity.

## Findings

**1. Ensembling does not recover the signal.** K=1 48.8% → K=5 50.3%. The
improvement is 1.5 points, well inside noise. Five independent reconstructions
agree no better than one.

**2. H2 did not replicate, and this is the important methodological result.** Net
exposure scored 56.7% at p = 0.030 on the K=1 data that suggested it, and
**49.6% at p = 0.949** on the independent K=5 data. It was pre-registered
precisely because it was found by searching five decision rules. Had it been
reported from the discovery data it would have been a false positive in print.
This is the second hypothesis in this project to die between discovery and
confirmation (see ch. 8 and ch. 10).

**3. The reformulation fixes the *bias* but does not create *signal*.** The
published method scores **43.5%** directional — below chance, p = 0.056, i.e.
actively pointing the wrong way, consistent with the provenance confound of
ch. 8. Guard contrast moves this to 48.8%, consensus to 50.3%: the anti-signal is
removed, and nothing replaces it. **Chance is the ceiling reached, not the floor
escaped.**

**4. Why ensembling could not have worked, in hindsight.** Consensus reduces
*variance* across samples. It cannot add *information*. All K samples are drawn
from the same specification, and ch. 8 established that the specification does
not contain the property the fix restores — 47.7% of cases mention none of the
changed identifiers, and the spec is derived from the vulnerable version in the
first place. Averaging five draws from an information-poor source yields a
lower-variance estimate of the same missing information.

We should have predicted this. The 2×2 in ch. 10 showed reconstruction quality
binds under the narrow question, and we reached for the standard variance-
reduction tool without asking whether the deficit was variance or information.
It was information.

## Conclusions

**The single-version spec-reconstruction method does not work, and we now know
why in a way that is not model-dependent, not metric-dependent, and not
prompt-dependent.** Three reformulations of increasing sophistication — narrow
question, per-side rating, five-sample consensus — all land at chance. The
binding constraint is the information content of the specification, and no
change to the generator, the judge, the rubric, the metric or the ensemble size
addresses that.

## Weaknesses

- K=5 may simply be too small; K=20 might behave differently. We consider this
  unlikely given the flatness of the coverage curve and the mechanism above, but
  it is untested.
- Temperature 0.8 was chosen for diversity without tuning; a different sampling
  regime might produce more genuinely varied defensive choices.
- 55.2% tie rate means coverage is only 44.8%; a rubric producing finer-grained
  scores would decide more cases, though the coverage curve gives no reason to
  expect the extra ones to be more accurate.
- One case excluded on prompt size (0.26%).
- Single seed.

## Pros and cons

**Pro**: fully within the premise; attacks Finding 2 at its source for the first
time in the project; pre-registered, so its null is trustworthy rather than a
tuning artefact. **Con**: 5× the generation cost of the published method for no
measurable gain; and it treats a variance problem that turned out to be an
information problem.

## What it changed in our beliefs

Closed the last lever that operates on the *generator* side. Combined with ch. 3
(more context), ch. 4 (bigger model) and ch. 6 (perfect reconstruction), every
way of improving the candidate has now been measured and none moves the result.
The remaining explanation is the one ch. 8 supplies: the specification does not
carry the information, and in this corpus it actively carries the wrong
information.

---

# Chapter 12 — Defensive reconstruction with explicit guard claims *(in flight)*

**Directory**: `experiments/2026-08-21_defensive-claims/`

*Written before the run, so the motive is on record ahead of the result.*

## Question

Every lever so far has tried to make the reconstruction a *better implementation*.
What if the reconstruction's job is not to be good code, but to **state what the
specification requires defensively** — and the judge's job is to check those
specific claims one at a time?

## Why we expect it to work — and why the previous three failures do not rule it out

Chapter 11 concluded that the deficit is information, not variance. That is
correct as far as it goes, but it conflates two different sources of information:

1. **What the specification says.** Established as poor (ch. 8): 47.7% of specs
   mention none of the changed identifiers, and specs are derived from the
   vulnerable version.
2. **What ordinary secure-coding practice implies for a function of this
   shape.** *Never tested.* A model asked to implement "copy `len` bytes from
   `src` into a fixed buffer" will bound the copy whether or not the spec
   mentions bounds — not because the spec said so, but because that is what
   competent C looks like.

Source 2 is genuine information the reconstruction can contribute that the
specification does not contain. Every arm so far has suppressed it: the published
generator prompt says to implement *"exactly as specified"* and to make *"the
standard, conventional engineering choice"* where the spec is silent. That
instruction optimises for faithfulness to a spec we now know describes the
vulnerable code. **We have been asking the generator to reproduce the bug.**

Two changes follow, both still strictly spec-only:

- **Ask for a defensively hardened implementation.** The mechanism is direct: if
  the candidate performs guard G, the vulnerable reference lacks G and the fixed
  reference has it, the comparison separates them. For the 196 anticipatable
  cases G is exactly what the patch added.
- **Ask the generator to state its guards explicitly**, with the input each one
  protects against. This converts the judge's task from open-ended comparison —
  which ch. 6 showed it performs lexically — into **per-claim verification**:
  *does this reference perform this specific check?* Checking one named property
  against one function is a far more reliable judgement than rating the overall
  similarity of two functions, and it sidesteps the baseline gap by construction,
  because irrelevant differences are never asked about.

It also makes the output **localising**: the method reports *which* guard is
missing, not just a score. No arm so far has produced that, and it is what a
practitioner would actually need.

## Why this is still the same method, not a different one

All three constraints from ch. 0 hold. The Generator sees only
`{language, docstring}` — no code, no CVE metadata. The Judge sees one reference
at a time and is never told which. No supervised labels. What changes is the
generator's *instruction* (spec-only throughout) and the judge's *question*. The
premise never specified that the reconstruction must be maximally faithful rather
than maximally careful; that was an implementation choice, and ch. 8 shows it was
the wrong one for this corpus.

## What we are doing

- **Stage 1** — new generator prompt: write a defensively hardened implementation
  from the spec alone, and emit an explicit list of the defensive steps taken,
  each with the hostile input it protects against. New `prompt_sha`, recorded;
  the published generator is untouched.
- **Stage 2** — judge, one reference at a time: given the spec and the guard
  list, decide for each claimed guard whether the reference **performs it**,
  **omits it**, or whether it is **not applicable** (the reference does not do
  the dangerous thing at all). The `not_applicable` escape is essential — without
  it every guard the reconstruction invents for a construct the real code does
  not use would count as a false omission.
- Score = severity-weighted count of guards the reference omits.

## Pre-registration

Primary: directional accuracy, chance 50%, ties as coverage. One test,
p < 0.05. Secondary, reported but not claimed: the same anticipatable /
domain-specific split as ch. 10–11.

**Prediction**: above chance overall, and larger on the anticipatable stratum. If
this fails too, the conclusion is that the method cannot be rescued within its
premise, and the bounded-negative result of ch. 4–11 is the finding.

## Expected weaknesses regardless of outcome

- A hardened generator may produce guards that neither reference performs,
  inflating omission counts on both sides and re-creating the baseline gap in a
  new place. The `not_applicable` category is the mitigation; whether the judge
  uses it honestly is an empirical question.
- Asking for hardening is a nudge toward the answer for the *class* of CVE that
  consists of a missing standard check. It is not label leakage — no
  vulnerability information reaches the generator, and the nudge is identical for
  both references — but the paper must state plainly that the method is now
  tuned toward one CVE family, and report the domain-specific stratum honestly as
  the control.
- Two prompts change at once (generator instruction and judge question), so a
  positive result cannot be attributed to one without a follow-up ablation.

## Results

376 of 392 judged (`C_1313__0` oversize; a few generation failures).

### The pre-registered primary test passes — marginally

| score | decided | coverage | accuracy | 95% CI | p |
|---|---|---|---|---|---|
| **severity-weighted omissions (primary)** | 210 | 55.4% | **57.1%** | [50.5%, 63.8%] | **0.0451** |

And the pre-registered secondary — the dissociation — appears in the predicted
direction for the first time in this project:

| stratum | decided | accuracy | 95% CI | p |
|---|---|---|---|---|
| fix adds an anticipatable defensive step | 111 | **60.4%** | [51.0%, 69.9%] | 0.036 |
| domain-specific / other (**control**) | 99 | 53.5% | [44.0%, 63.0%] | 0.547 |

Progression across the four formulations:

| arm | directional accuracy |
|---|---|
| published method (5-way taxonomy) | 43.5% |
| guard contrast, K=1 | 48.8% |
| consensus guard, K=5 | 50.3% |
| **defensive claims (ch. 12)** | **57.1%** |

## Why we are NOT claiming this yet

The test passed by the stated rule. Four things say hold:

1. **p = 0.0451 is barely under threshold** and the CI barely excludes 50%
   ([50.5%, 63.8%]).
2. **The mechanism diagnostics look wrong.** Mean omissions per case are
   *identical* across sides — vulnerable 1.50, fixed 1.49. The entire signal
   comes from severity weighting: mean score 7.81 vs 7.60, a delta of **+0.22**
   on a mean of ~7.8. A working detector should separate the *counts*, not
   rely on a 3% difference in a subjective severity rating.
3. **The `not_applicable` escape is underused.** Verdict mix over 3022 claim
   checks: performs 51.3%, **omits 37.6%**, not_applicable 11.1%. The judge is
   calling mature production code "omitting" a claimed guard more than a third of
   the time, which is not credible and is exactly the failure mode the
   `not_applicable` verdict was designed to prevent. The score may be measuring
   how confidently the judge hallucinates omissions rather than which side is
   worse.
4. **The dissociation is not clean at category level.** Within the control
   stratum, `other_modification` — its largest category — scores 60.6% (n=66),
   above the anticipatable stratum's average. If the mechanism were as claimed,
   the control's biggest bucket should not be its strongest.

Most of all: **this project has already produced a 56.7% at p = 0.030 that became
49.6% at p = 0.949 on independent data** (ch. 11, H2). A marginal p-value in
exactly this setting has burned us once. Treating this one as a finding without
replication would repeat the mistake with a shorter memory.

## Replication — the deciding test

Re-running the whole arm at **seed 5678** (fresh generations, fresh judgements,
everything else identical). Pre-registered before the replication data exist:

- **Replicates** if directional accuracy is above 50% with p < 0.05 on the
  primary score. Then ch. 12 is a genuine positive result and the first working
  variant in the project.
- **Fails** if it lands at chance. Then ch. 12 joins chs. 10 and 11, the
  bounded-negative conclusion stands unchanged, and the arc gains a fourth
  worked example of why single-run marginal significance is not evidence.

Either way the seed-1234 numbers above stay in this log exactly as recorded.

### Result: it does not replicate

| | decided | accuracy | 95% CI | p |
|---|---|---|---|---|
| seed 1234 (original) | 210 | 57.1% | [50.5%, 63.8%] | 0.045 |
| **seed 5678 (replication)** | 225 | **53.3%** | **[46.9%, 59.9%]** | **0.351** |

**The pre-registered replication fails.** And the dissociation — the secondary
prediction, and the part that carried the mechanism story — does not merely
weaken, it **reverses**:

| stratum | seed 1234 | seed 5678 |
|---|---|---|
| anticipatable defensive step | 60.4% (p=0.036) | **52.8%** (p=0.59) |
| domain-specific (control) | 53.5% (p=0.55) | **54.0%** (p=0.48) |

In the replication the *control* stratum outscores the stratum the mechanism
predicts should work. Whatever produced the seed-1234 dissociation, it was not
the mechanism we proposed.

### Pooling, and why it does not rescue the result

Pooling both runs (a post-hoc decision, made after seeing that one failed —
disclosed as such):

| | decided | accuracy | binomial p | **CVE-clustered 95% CI** |
|---|---|---|---|---|
| pooled | 435 | 55.2% | 0.035 | **[49.9%, 60.5%]** |

The binomial p and the clustered CI disagree, and **the CI is the one to
believe**: the binomial test assumes case-level independence this corpus does not
have (435 decided cases over ~300 CVEs, half from one repository). Corrected for
clustering, the pooled interval includes 50%. This is the same error chapter 5
found in the original write-up, reappearing in our own analysis — worth recording
precisely because we caught it in ourselves.

### What survives: a small, consistent, sub-resolution effect

The per-case score delta is positive in **both** runs and by a similar amount:

| run | mean delta (vuln − fixed) | cases positive | negative | zero |
|---|---|---|---|---|
| seed 1234 | **+0.216** | 120 | 90 | 169 |
| seed 5678 | **+0.296** | 120 | 105 | 157 |

Consistent sign, consistent magnitude, on a scale whose mean is ~7.7. The honest
statement is: **there may be a small real effect here, of order 55% directional
accuracy, and it is below the resolution this corpus can establish.** It is not a
working detector, and it must not be reported as one.

## Conclusions

**Chapter 12 does not establish a working method.** The pre-registered primary
passed once at p = 0.045 and failed on replication at p = 0.351; the mechanism
prediction reversed; pooled, the clustered CI includes chance.

The three warning signs recorded *before* the replication all proved
well-founded: identical omission counts across sides (1.50 vs 1.49), an
implausible 37.6% `omits` rate with `not_applicable` at only 11.1%, and a flat
coverage–accuracy curve. Each said the seed-1234 result was not measuring what it
appeared to measure. Recording them in advance is what makes the replication
interpretable rather than a disappointment.

## What it changed in our beliefs

The hypothesis was good and remains the most plausible remaining one: secure-coding
priors *are* information the specification lacks, and the published generator
prompt *was* suppressing them. The consistent positive delta across seeds is
weakly consistent with that. But the effect, if real, is far too small to build a
detector on, and the corpus cannot resolve it.

**Four reformulations — narrow question, per-side rating, five-sample consensus,
defensive claims with per-claim verification — have now been measured. None
produces a reliable detector.** Combined with four generator-side levers (bigger
model, more context, perfect reconstruction, ensembling) also measured and null,
the bounded-negative conclusion of chapters 4–11 stands, now with the strongest
available evidence that it is not for want of trying.

## Weaknesses (independent of the replication outcome)

- Two prompts changed at once (generator instruction, judge task), so a positive
  result cannot be attributed to either without a follow-up ablation.
- Asking for hardening nudges toward the missing-standard-check CVE family. Not
  label leakage — no vulnerability information reaches the generator and the
  nudge is identical for both references — but the method is now tuned toward one
  family, and the domain-specific stratum must always be reported as the control.
- Coverage is 55.4%; the coverage–accuracy curve is flat to slightly declining
  (57.6% at margin ≥2, 53.3% at ≥6), so there is **no confident subset**. A
  working detector would usually be more accurate where it is more certain. This
  is further reason for caution.
- 44.4% tie rate.

## What it changed in our beliefs

Provisionally: **secure-coding priors are a real information source the
specification does not contain**, and instructing the generator to be faithful
rather than careful was suppressing them. If it replicates, that is the paper's
positive contribution and it reframes the whole negative arc — the method was
never given the one input that could make it work. If it does not replicate, the
conclusion of ch. 11 stands and the failure is complete.

---

# Running summary — what we believe now

| Claim | Status | Evidence |
|---|---|---|
| The method fails at corpus scale | **Established** | ch. 4, 5 |
| Not because the generator is weak | **Established** | ch. 6 (L1 = 14.6% vs 16.0%) |
| Not because more context is missing | **Established** | ch. 3 |
| Not because the judge is incapable | **Established** | ch. 9 (84.4%) |
| The judge compares text, not behaviour | **Established** | ch. 6 (L0→L1, 34.6% vs 6.8%) |
| PFA's chance level is 25%, and it rewards asymmetry | **Established** | ch. 7 |
| Every single-version formulation is at chance | **Established** | ch. 7 |
| The specs are derived from the vulnerable code | **Established** (correlational) | ch. 8 (p=2.9e-6) |
| 28.3% of vulnerable snippets are mis-extracted | **Established**, not causal | ch. 8 |
| The failure is in the task formulation | **Strongly supported** | ch. 9 vs 4 |
| Reconstruction quality binds under the right question | **Supported** | ch. 10 (2×2) |
| Ensembling recovers the signal | **Refuted** | ch. 11 (50.3%, p=1.0) |
| The narrow question removes the anti-signal but adds none | **Established** | ch. 10–11 (43.5% → 50.3%) |
| The spec is too information-poor to work | **Supported**, mechanism-level | ch. 8 + ch. 11 |
| Secure-coding priors can supply what the spec lacks | **Failed replication**; small consistent effect, sub-resolution | ch. 12 (57.1% → 53.3%) |
| Marginal single-run significance replicates here | **Refuted twice** | ch. 11 H2 (0.030→0.949), ch. 12 (0.045→0.351) |
| Any variant within the premise yields a reliable detector | **Refuted across 4 reformulations** | ch. 10, 11, 12 |

## Open threads, ranked

1. **Ch. 11 result** — in flight.
2. **The provenance causal test** (`respec.py`, scripted, unrun). Diagnostic
   only; must not be presented as a method improvement.
3. **Semantic spec-sufficiency labels**, to replace the failed lexical proxy.
4. **Fix the extraction defect** and re-derive the corpus; the ~49% clean rate is
   optimistic.
5. **Seed variance** — everything so far is a single seed per arm.

## Methodological notes worth keeping for the paper

- Every arm is additive. `scripts/`, `cases/`, `results/`, `reports/`, `pilot/`
  and `.claude/` are unmodified throughout; the published arms stay
  byte-reproducible and `prompt_sha` still resolves to `1de29ae28c7d` wherever
  the rubric is meant to be unchanged.
- Two hypotheses have been rejected after looking promising at an interim
  checkpoint (ch. 8's lexical proxy, ch. 10's dissociation). Both are recorded in
  full. The pre-registration that caught the second is itself a result worth
  describing.
- Three claims in the original chapter-4 write-up were corrected by chapter 5.
  The paper should present the corrected versions, and may find the correction
  itself worth a paragraph.
