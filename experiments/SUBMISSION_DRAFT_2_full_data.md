# Unsupervised Vulnerability Detection by Specification Reconstruction

### How the question you ask the judge decides whether the method works
### Results on 626 CVE fix-pairs spanning 453 CVEs

---

> ### Status of the headline claim
>
> | result | status |
> |---|---|
> | Original formulation — **46.1%**, at chance | **Confirmed.** |
> | **Final formulation — 66.8%** | **One seed. Replication in flight.** Not to be claimed until the second seed returns. |
>
> The rest of this document reads as though the replication holds. If it does not,
> §7 and §9 are the sections that change.

---

## Abstract
 
We test whether a vulnerability can be found without labels, without training,
and without any prior description of the vulnerability — using only the
function's own documentation. A language model that has never seen the code
writes implementations from the docstring alone; a second model is shown one
version of the real function at a time, never told which version it is, and asked
how it compares.

The naive form of this idea does not work. Asked a broad question — *how
similar is this implementation to that one?* — against a single reconstruction,
the method sits at chance: **46.1%** on 626 CVE fix-pairs (p = 0.22). Our central
result is that the failure is in **the question put to the judge and the number
of reconstructions it is asked about**, not in the idea, the generator, or the
data.

Two changes fix it. First, we replace the broad similarity question with a narrow
one: *which defensive steps does the reconstruction perform that this version
omits?* Second, we replace the single reconstruction with **five independent
ones** and ask only about steps a **majority** of them take — separating what the
specification implies from what one sample happened to write.

The resulting method reaches **66.8%** on the same corpus, same model, same
metric (95% CI [60.4%, 73.3%], p = 1.6 × 10⁻⁶ against a 50% chance level), with
no supervised signal of any kind. That is **+20.7 points from reformulating the
LLM task alone.** Accuracy is *highest* — 68.5% — on the subset where the two
versions have identical line counts and the obvious surface shortcut is
unavailable.

Along the way we measure why the broad question fails: an LLM judge asked to
compare two implementations is doing something substantially **lexical**.
Replacing the reconstruction with the genuine patched function *with local
variables renamed* — semantically identical, textually different — costs 25
points of accuracy and 0.21 of AUC. That constrains any LLM-as-judge
code-comparison design, well beyond this method.

---

## 1. The idea

Supervised vulnerability detection learns from labelled examples of past
vulnerabilities and generalises poorly to classes it has not seen. We ask whether
the **specification** can play the role of the label.

Documentation describes what a function is *supposed* to do. An independent
implementer working only from that description produces code that embodies the
specification without inheriting the original's mistakes. Where the real code and
the independent reconstruction diverge, one of three things has happened: the
documentation is incomplete, the implementation has drifted from it, or the
implementation has a defect. The third case is what we are hunting.

This requires no labelled data, no training, and no vulnerability taxonomy — only
documentation, which most production codebases already have.

The idea is simple to state and, as we found, easy to implement in a form that
does not work at all. §2 is the account of how it was made to work.

---

## 2. How the method evolved

Every configuration below runs on the same corpus, the same model, the same seed,
and is scored by the same metric (§4). Only the **generator and judge
formulation** changes.

### 2.1 v1 — a broad similarity question, one reconstruction

The natural first implementation. Generate one implementation from the docstring;
show the judge the reconstruction and one version of the real function; ask it to
rate behavioural and semantic similarity and to assign a category from five
(equivalent, quality bug, functional mismatch, security concern, degenerate).
Whichever real version is judged more divergent is called the vulnerable one.

**Result: 46.1%** on the decided subset (n = 269, CI [40.2%, 52.1%], p = 0.22).
Chance is 50%. The formulation carries no signal at all.

Three explanations were available, and we tested each rather than choosing one:

| hypothesis | test | outcome |
|---|---|---|
| the generator is too weak | a stronger generator model | no effect |
| the generator lacks context | wider context ablation | negative |
| the reconstruction is too unfaithful | replace it with the **genuine patched function** | **no effect** — see §2.2 |

### 2.2 What we learned: the judge is comparing text, not behaviour

The decisive experiment was an oracle ablation. Instead of a generated
reconstruction, hand the judge a **perfect** one — the genuine patched function
itself — then degrade it only in ways the rubric explicitly declares irrelevant.

| rung | candidate handed to the judge | accuracy | ROC-AUC |
|---|---|---:|---:|
| L0 | patched function, verbatim | **39.7%** | 0.887 |
| L1 | patched function, locals renamed, comments stripped | **14.6%** | 0.674 |
| L3 | generated from the specification (= v1) | 16.0% | 0.475 |

*(Paired Flag Accuracy, chance 25% — the metric v1 was pre-registered on. See
§4.3. Not comparable to the 50%-chance figures elsewhere; the ordering is the
point.)*

L0 and L1 are the **same function**: same behaviour, same control flow, same
semantics. The rubric states in as many words that *"different variable names,
different type/struct names, different helper function names, or different code
style are **not** behavioral differences."* Renaming locals anyway costs **25
points and 0.21 of AUC**. The internal control inside L1 removes any doubt:

| L1 subset | n | accuracy |
|---|---:|---:|
| 0 identifiers renamed (reformatting only) | 26 | **34.6%** |
| 5 or more identifiers renamed | 219 | **6.8%** |

Two conclusions followed, and they set the whole subsequent direction:

1. **An LLM judge's apparent ability to compare two implementations
   behaviourally is largely lexical.** A broad "how similar are these?" question
   invites it to measure surface overlap, because surface overlap is what it can
   actually measure.
2. **L1 ≈ L3: a perfect reconstruction scores the same as a generated one.**
   Reconstruction *fidelity* was never the binding constraint. Improving the
   generator could not have helped, which is exactly what the two generator
   experiments in §2.1 had already found empirically.

If the candidate is not the problem, the **question** is. An independent
reconstruction shares almost no identifiers with the original by construction,
which places it at the far end of the degradation curve above. A question
answerable by lexical comparison is therefore the worst possible question to ask
in this setting.

### 2.3 Change #1 — narrow the judge's task

We replaced the broad similarity rating with a single, specific, non-lexical
question:

> **Which defensive steps does the reconstruction perform that the target does
> not?**

with "defensive step" enumerated concretely — a bounds or length check before an
access, a null or error-return check before use, an arithmetic overflow guard, an
initialisation or clearing before use, a lifetime step (free, unlock, refcount,
nulling after release), input validation, a permission check, an explicit bound
on work or memory. The judge returns an **exposure score**: how much
hostile-input exposure the omissions leave.

The rubric also states what is *not* a difference — naming, types, helper
functions, control-flow shape, error-handling style, formatting, comments,
length — and requires the same effect achieved differently (`if (n > max) return
-EINVAL` versus `n = MIN(n, max)`) to count as the same step. This closes the
lexical escape route §2.2 exposed.

**That the narrow question is the right one is directly measurable.** Asked of
two real versions shown side by side, it scores **82.4%** (§7.3) where the broad
question scored at chance. The question, not the model, was the constraint.

But asked of a **single** reconstruction — the legal, deployable form — it scored
**48.8%**. Still chance.

### 2.4 What we learned: one reconstruction rarely contains the guard

The failure had a visible mechanism. With one reconstruction, the judge rated the
real function's exposure at **0 in 63% of vulnerable and 61% of patched calls**,
with mean exposure 1.31 against 1.37 — a −0.06 delta, marginally the wrong way.

The reason is structural: a from-spec reconstruction written by an LLM is
genuinely *less* defensive than mature production code. Comparing real kernel
code against one such sample usually finds nothing the sample does that the real
code doesn't, so the score is 0 on both sides and the pair is undecidable.

A single sample also cannot distinguish its own arbitrary choices from the
specification's requirements. Any one draw from a stochastic generator contains
both, and nothing separates them.

### 2.5 Change #2 — consensus across five independent reconstructions

So we stopped asking about *a* reconstruction and started asking about what
independent implementers **agree** on. Five samples at temperature 0.8, and the
judge is instructed:

> *"Ignore any step that only one implementation performs. Require at least a
> majority of them before you treat a step as expected."*

The logic: a defensive step that four or five of five independent implementers
take is a property of the **specification** and of ordinary practice for that
kind of function. A step only one takes is **sampling noise**. Consensus
separates the two — and it does so without a single label, which is what keeps
the method unsupervised.

This also repairs §2.4's mechanism directly. The union of five reconstructions is
far more likely to contain the guard the vulnerable version lacks than any one of
them, while the majority requirement stops that union from becoming a list of
five implementers' idiosyncrasies.

The rubric additionally rates the **reverse** comparison — how exposed the
reconstructions are by steps the target performs and they omit — as an explicit
control, which makes the target's own rating interpretable and yields a second
decision rule (§7.2).

### 2.6 The progression, measured

| | judge's question | reconstructions | **accuracy** | 95% CI | p vs 50% |
|---|---|---:|---:|---|---:|
| **v1** | broad similarity, 5-way category | 1 | **46.1%** | [40.2%, 52.1%] | 0.22 |
| **v2** | narrow: omitted defensive steps | 1 | **48.8%** | [41.4%, 56.3%] | 0.82 |
| **v3 — the method** | narrow: omitted defensive steps | **5, majority** | **66.8%** | **[60.4%, 73.3%]** | **1.6 × 10⁻⁶** |

**+20.7 points from reformulating the LLM task.** Same model, same corpus, same
metric, same seed, no supervised signal added at any step. The generator changed
only in how many times it was sampled; the judge changed only in what it was
asked.

Neither change is sufficient alone. The narrow question without consensus is at
chance (v2); consensus was only worth trying *because* §2.2 had shown the
question was the constraint and §2.4 had shown one sample could not answer it.

> **One measurement is outstanding.** v2 was measured before our data-validation
> pass (§5) and has not been re-run on the final corpus, so the v1 → v3 gain is
> established on identical data while the internal split between the two changes
> is not yet isolated on it. §10.2 is the ablation that would separate them.

---

## 3. The final method

### 3.1 The three stages

**Stage 1 — Reconstruction.** A generator model receives exactly
`{language, docstring}` and writes an implementation. It never sees the real
code, the CVE identifier, the repository, or the commit message. We draw **five
independent samples** at temperature 0.8.

**Stage 2 — Judgement.** A judge model receives the specification, the five
reconstructions, and **one** version of the real function — the *target*. It
answers the §2.3 question about majority-performed defensive steps and returns an
**exposure score** on 0–10.

**Stage 3 — Comparison.** The harness runs stage 2 twice per case: once with the
vulnerable version as target, once with the patched version. The judge is never
told which is which, and the two calls are independent — neither sees the other's
input or output. The detector's answer is: **whichever version received the
higher exposure score is the vulnerable one.**

### 3.2 A worked example

Take a function whose docstring says it copies a caller-supplied buffer into a
fixed-size destination.

1. Five models independently implement it from that sentence. Four of the five
   write a length check before copying, because the specification implies one.
   *Four of five is a majority — this is a specification property, not one
   author's habit.*
2. The judge is shown **version A** and asked what it omits relative to the
   consensus. It reports: *no bound on the copy length; reachable with an
   oversized input.* Exposure score **6**.
3. The judge is shown **version B**, in a separate call. It reports: *performs the
   length check.* Exposure score **0**.
4. The harness concludes **version A is the vulnerable one**. It happens to be
   right — but nothing in steps 1–3 knew that.

Under v1 this same case would have produced two similarity ratings dominated by
the fact that neither real version looks much like an LLM's reconstruction.

### 3.3 The three constraints

These are what make the result meaningful rather than circular:

1. **Information isolation.** The generator sees only `{language, docstring}`.
   Enforced structurally: the request body is built from those two fields, so
   nothing else can reach it.
2. **One version at a time.** The judge compares against a single version and is
   never told which it is, or that a vulnerability is involved.
3. **No supervised signal.** The vulnerable/patched pairing exists only in the
   evaluation harness. The detector never sees a label.

Any experiment that relaxes a constraint is labelled a **diagnostic** and is never
reported as the method. §7.3 is the only such result here.

---

## 4. How we measure — what "accuracy" means

This section defines every number in §2.6 and §7. It is worth reading before the
results, because the metric is not the one used in standard classification.

### 4.1 The unit of measurement is a pair, not a function

Every case gives us **two** versions of the same function: the one before the
security patch and the one after. We know which is which; the detector does not.
This is what makes evaluation possible without labelled vulnerability data — the
pairing itself is the ground truth.

### 4.2 Accuracy = did the vulnerable version score higher?

For each case we obtain two scores, one per version. Then:

| outcome | meaning | counted as |
|---|---|---|
| vulnerable score **>** patched score | the detector ranked the pair correctly | **correct** |
| vulnerable score **<** patched score | the detector ranked the pair backwards | **wrong** |
| the two scores are **equal** | the detector did not distinguish them | **undecided** |

**Accuracy is the fraction of *decided* cases the detector ranked correctly.**

$$\text{accuracy} = \frac{\text{cases where vulnerable scored higher}}{\text{cases where the two scores differ}}$$

**Chance is exactly 50%.** A detector with no information, forced to pick one of
two versions, is right half the time. There is no class-imbalance correction to
argue about: every case has exactly one vulnerable and one patched version, so the
baseline is 50% by construction and cannot be moved by how often the detector
chooses to flag anything.

Applying this one metric to v1, v2 and v3 alike is what makes §2.6 a like-for-like
comparison.

### 4.3 A note on the earlier metric

v1 was pre-registered on **Paired Flag Accuracy** — the vulnerable side receives
the `security_vulnerability_concern` category and the patched side does not. That
metric has a chance level of **25%**, not 0%, because a detector flagging each
side independently with probability *p* scores *p*(1−*p*); it also counts ties as
failures, and rewards asymmetry between the two calls rather than correctness.
Constant predictors ("always flag", "never flag") both score 0%.

We report it only where an experiment was run on it (§2.2, Appendix A), always
labelled, and never alongside 50%-chance figures without that label. §4.2 is the
metric for every comparison that matters.

### 4.4 Coverage: how often the method answers at all

**Coverage is the fraction of cases that are decided** — where the two scores
differ. Ties are reported as coverage and are *never* counted as successes or
failures, because scoring them either way would let us manufacture whatever number
we wanted.

> Accuracy is therefore **conditional on answering**. The method at 66.8% and 38%
> coverage answers roughly two cases in five and is right on about two of every
> three it answers. §6.1 explains mechanically where the coverage goes, and §7.2
> gives a second operating point that trades accuracy for it.

### 4.5 Confidence intervals resample CVEs, not cases

One CVE commit often patches several functions, and those cases succeed or fail
together — they are not independent observations. So all intervals here are
**CVE-clustered bootstraps**: we resample whole CVEs with replacement 10,000
times, recompute the accuracy on each resample, and take the 2.5th and 97.5th
percentiles. This is stricter than the textbook binomial interval, and it is why
our intervals are wider than a naive calculation would give.

The p-value is an exact two-sided binomial test against 50%.

---

## 5. Data

`D.zip`: 553 CVE fix commits, extracted into 792 function-level cases. Each case
is one function in two versions — pre-patch and post-patch — with a structured
docstring (Summary, Parameters, Returns, Logic).

| | |
|---|---:|
| cases extracted | 792 |
| **usable cases** | **626** (79%) |
| non-duplicate cases (evaluation subset) | **539** |
| unique CVEs | **453** |
| languages | 595 C, 31 C++ |

Repositories: `torvalds/linux` 337, ImageMagick 47, chromium 45, FFmpeg 15,
krb5 12, radare2 9, others. Because 54% of cases come from a single repository,
every interval in this paper is CVE-clustered (§4.5) rather than case-level.

87 of the 626 cases are marked `duplicate_of` — the same function reached through
more than one CVE record. The pre-registered evaluation subset excludes them; the
full 626 is reported alongside as descriptive.

**Validation.** Function extraction from patch line-ranges is error-prone, and an
error affecting one side of a pair biases a paired metric directly. Every case is
therefore validated against the raw archive by `scripts/validate_corpus.py`
before use, with both sides extracted by the same brace-matching code path: the
snippet must be a verbatim substring of the original file, both versions must be
exactly one complete function, the recorded line range must agree with the
snippet, the two versions must differ, and the docstring must be present and
non-trivial. Cases that cannot be posed as a reconstruction task at all — patched
line at file scope, `#define` macros with statement-expression bodies, functions
renamed by the patch — are excluded rather than repaired. The corpus is
content-addressed (`corpus_sha`) and validation is a gate on every run, so no
result in this paper can be produced against an unvalidated corpus. An earlier,
unvalidated extraction of this dataset failed these checks on the pre-patch side
and is not used anywhere here.

---

## 6. Experimental setup

Qwen3-32B-AWQ served locally via vLLM on a single RTX 4090, in both the generator
and the judge role. Grammar-constrained JSON decoding, so every response parses.
Generator temperature 0.8 for the five samples; judge temperature 0.0; seed 1234.
All 626 cases judged at the full K = 5; none degraded on context length.

Every result record carries a digest of the exact rubric text (`prompt_sha`) and
of the corpus (`corpus_sha`), so any figure can be traced to the prompt and the
data that produced it.

No API costs. A full 626-case pass takes a few GPU-hours at K = 5 on one consumer
card.

### 6.1 What the exposure score actually looks like

The rubric asks for 0–10. In practice the judge uses three values.

| exposure | 0 | 1 | 2 | 3 | **4** | 5 | **6** | 7 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| vulnerable side | 79 | 5 | 7 | 14 | **362** | 8 | **148** | 3 |
| patched side | 104 | 2 | 8 | 29 | **361** | 13 | **104** | 5 |

The rubric binds ranges to severity classes — 0 for "omits nothing", 1–3 for "hard
to reach", 4–6 for "a plausible issue on a reachable path", 7–10 for "clear and
serious" — and the judge answers at the *class*, not within it. **92% of all
scores are exactly 0, 4 or 6.**

This explains the coverage number mechanically. Two versions of the same function
usually fall in the same severity class, and when they do the scores are identical
and the case is a tie. 62.3% of cases tie, and only 14.4% of those ties are the
"both clean" case where both sides score 0. The rest are two functions the judge
placed in the same band.

Coverage is therefore not a property of the idea; it is a property of a rubric
that quantises to three levels — and the most direct route to raising it is a
score decoupled from the severity class (§10.3).

The direction is right even in the aggregate: mean exposure is **3.93** on
vulnerable versions against **3.63** on patched ones.

---

## 7. Results

### 7.1 The method: 66.8%

Five reconstructions per case, judge sees one version at a time, all three
constraints intact.

| set | cases | decided | coverage | **accuracy** | 95% CI (CVE-clustered) | p vs 50% |
|---|---:|---:|---:|---:|---|---:|
| **539 non-duplicate — pre-registered primary** | 539 | 205 | 38.0% | **66.8%** | **[60.4%, 73.3%]** | **1.6 × 10⁻⁶** |
| 626 all cases — descriptive | 626 | 236 | 37.7% | 65.3% | [59.1%, 71.4%] | 3.2 × 10⁻⁶ |

Read plainly: **of the 205 pairs the method was willing to rank, it put the
vulnerable version on top 137 times.** The interval clears chance by ten points at
its lower end.

Nothing supervised entered this number. The generator saw a docstring. The judge
saw one function at a time and was never told what it was looking at. The
vulnerable/patched labels exist only in the scoring harness.

### 7.2 A second operating point

The decision rule in §3.1 uses the target's own exposure. The rubric also records
`consensus_exposure` — the reverse comparison introduced in §2.5. Differencing the
two removes the offset common to both judge calls (a weak reconstruction makes
everything compared against it look defensively better) and decides substantially
more cases:

| decision rule | decided | coverage | accuracy | 95% CI |
|---|---:|---:|---:|---|
| target exposure (§3.1) | 236 | 37.7% | **65.3%** | [59.1%, 71.4%] |
| net exposure (target − consensus) | 344 | **55.0%** | 59.0% | [53.8%, 64.2%] |

Both exclude chance. The method is therefore tunable across a genuine
coverage–accuracy frontier rather than fixed at one operating point: 17 points of
coverage cost 6 points of accuracy.

What does *not* work is thresholding. Demanding a larger score margin buys
nothing, because §6.1's quantisation means the margin carries almost no
information beyond its sign:

| minimum margin | ≥1 | ≥2 | ≥3 | ≥4 |
|---|---:|---:|---:|---:|
| decided | 236 | 188 | 82 | 61 |
| accuracy | 65.3% | 67.6% | 63.4% | 67.2% |

There is no confident subset to extract. The useful knob is the score definition,
not the threshold — §10.3.

### 7.3 The narrow question with both versions: 82.4%

A **diagnostic** that relaxes constraint #2 (§3.3): the judge is shown both real
versions at once in randomised order and asked which is missing a guard.
`neither` is permitted and scored as an abstention, so accuracy cannot be inflated
by forcing guesses.

| set | cases | decided | coverage | **accuracy** | 95% CI |
|---|---:|---:|---:|---:|---|
| 539 non-duplicate | 539 | 452 | 83.9% | **82.3%** | [78.6%, 85.9%] |
| 626 all cases | 626 | 533 | 85.1% | **82.4%** | [78.6%, 85.9%] |

This is the measurement referenced in §2.3: it isolates the *question* from the
*reconstruction* by removing the reconstruction entirely. The narrow question
carries strong signal; the broad question, given the same access, did not.

**It is not a deployable detector.** In the field you have one function, not a
matched pair — if you already had the patched version you would not need
detection. And §8.1 shows a meaningful share of the 82.4% is surface, so it should
be read as *what this judge does when handed the comparison*, not as a bound on
what is knowable in principle.

---

## 8. Controls

### 8.1 Length

Security patches usually *add* lines, so *"the shorter version is the vulnerable
one"* is a rule that needs no intelligence at all. On this corpus it is also
powerful: of 626 pairs, **415 have a shorter vulnerable side, 148 are equal
length, and 63 have a longer one** — so the rule is right on 86.8% of the pairs
where it applies. Any detector shown both versions can exploit it.

Stratifying by that structure:

| stratum | n (method / diagnostic) | **method** | both-versions diagnostic |
|---|---:|---:|---:|
| vulnerable side shorter | 154 / 377 | 66.9% | **92.0%** |
| **equal length — no length signal** | 54 / 100 | **68.5%** | 77.0% |
| vulnerable side longer | 28 / 56 | 50.0% | **26.8%** |

**The method is flat across the three strata and at its best where the shortcut is
unavailable**: 68.5% on equal-length pairs (CI [56.4%, 80.0%], excluding chance),
*above* its overall accuracy. A detector secretly ranking by line count could not
produce that row. Consistently, the method chooses the shorter side on 64.3% of
unequal decided pairs — almost exactly the 60.4% a length-blind, 65%-accurate
detector would produce by chance alone.

The both-versions diagnostic is a different story: 92.0% where length points the
right way, 26.8% where it points the wrong way, choosing the shorter side on 89.6%
of unequal pairs. Showing the judge both texts at once hands it the comparison the
shortcut lives in, and it takes it — a further instance of §2.2's lexical
dependence. This is why §7.3 is framed as a diagnostic rather than a ceiling.

**Constraint #2 turns out to be a defence, not only a cost.** The single-version
formulation is structurally immune to a shortcut that lives in the comparison,
because it never sees the two versions together.

It also generalises: paired CVE benchmarks carry a length prior strong enough that
a line-count rule outscores an LLM judge shown both versions. Any paired
evaluation on fix-pairs should report the equal-length stratum, and we suggest it
as a standard control for this literature.

### 8.2 Docstring leakage

32 of the 626 cases carry a heuristic flag for docstring text that may describe
the fix. Removing them changes nothing: **64.9% on the 594 unflagged cases**
(n = 225 decided) against 65.3% overall. An earlier LLM audit of the full corpus
removed docstrings that stated the fix outright.

### 8.3 Structural controls

- **Information isolation is structural, not prompt-based.** The generator's
  request body is constructed from two fields; it is not possible for code or CVE
  metadata to reach it.
- **The judge rubric is digest-pinned** (`prompt_sha`), so no arm can silently
  drift from the text it claims to use.
- **The two judge calls per case are independent** — neither is conditioned on the
  other's input or verdict.
- **The corpus is content-addressed** (`corpus_sha`) and validation-gated (§5).

### 8.4 It is not simply "ask the model"

Asked directly whether a single function is vulnerable, the same model flags only
~10% of vulnerable sides and lands at chance on AUC — worse than v1, let alone the
method. Supplying the specification alongside barely helps. A static analyser
(flawfinder) applied to these snippets does worse still, though that is partly a
property of bare functions with no headers or types. *(Appendix A, PFA scale.)*

The method's advantage is not access to the function. It is the question.

---

## 9. Limitations

**The headline result has been measured once.** A seed replication is in flight.
The effect is large (17 points above chance, p = 1.6 × 10⁻⁶), but it is not
established until a second seed returns. This project has twice seen marginal
single-run significance fail to replicate (Appendix A #7, #8), which is why the
banner at the top of this document is there.

**The two changes are not yet separated on the final corpus.** §2.6's v1 → v3 gain
is measured on identical data, but v2 — the narrow question with a single
reconstruction — was measured before the validation pass in §5. We attribute the
gain to the two changes jointly and do not claim a split between them. §10.2 is
the ablation that would resolve it.

**Coverage is 38%.** The method answers on 205 of 539 cases, and reported accuracy
is conditional on answering (§4.4). §6.1 explains the mechanism and §7.2 gives a
higher-coverage operating point, but a deployment would still need to know whether
the abstention region is benign or systematically conceals a vulnerability class.
We have not characterised it.

**The 28-case anti-length stratum is underpowered.** The method sits at 50.0%
there (CI [30.0%, 69.2%]). That interval is consistent with the 68.5% equal-length
result and with chance alike; it is not evidence either way, and it is the
smallest stratum in §8.1.

**One model family.** Qwen3-32B in both roles. Generator and judge share
pretraining, and the design does not exclude correlation arising from that.

**One dataset, dominated by one repository.** 54% of cases are Linux kernel code.
CVE clustering corrects the variance estimate, not the composition.

**The specifications were written alongside the pre-patch code.** Identifiers
unique to the pre-patch version appear in the docstrings 3.7× more often than
patched-only identifiers (470 mentions vs 127; sign test p = 2.9 × 10⁻⁶). This
biases *against* the method — a faithful reconstruction from such a specification
should resemble the vulnerable version — so the reported accuracy is if anything
understated. It is also not only a dataset artefact: in deployment a project's
docstring is written alongside the code it documents, which is the vulnerable
version right up until the patch lands. The causal test is unrun (§10.5).

**Scope.** C and C++, predominantly memory-safety and input-validation CVEs.
Nothing here speaks to logic flaws, race conditions, or managed-language
vulnerabilities.

**Ties are excluded, not resolved.** Reporting accuracy on the decided subset is
the honest choice available, but it means the method's behaviour on 62% of cases
is described only by its coverage.

---

## 10. Where this goes next

Ranked by what each would settle, all runnable locally at no marginal cost.

1. **Seed replication.** A second full pass at seed 5678, already half-generated.
   *Prediction on record: accuracy within the current CI.* This removes the banner
   at the top of this document.
2. **The K-ablation, K = 1 / 3 / 5, on the final corpus.** Reuses the candidate
   pool already on disk; only the judge re-runs. *Prediction: monotone increase in
   K, with the largest step between 1 and 3.* This is what separates §2.3's
   contribution from §2.5's, and it is the single most valuable missing run.
3. **A severity score decoupled from the severity class.** §6.1 shows the rubric
   quantises to three levels, the direct cause of the 62% tie rate. A score rated
   independently of the band should raise coverage substantially without touching
   the question — the highest-leverage remaining change to the method itself.
4. **Push K further, and vary sampling.** K = 5 was chosen without tuning, as was
   temperature 0.8. If §2.5's consensus mechanism is what drives the result, both
   should have measurable optima.
5. **The provenance causal test.** Regenerate specifications from the *patched*
   side and re-run. If the direction of the bias flips, the provenance of the
   specification sets the direction of the detector's bias — a design constraint on
   this whole family of methods. If it does not, provenance is exonerated.
6. **Cross-family generator ≠ judge.** Directly tests the shared-pretraining
   confound in §9, and would establish whether the result is a property of the
   formulation or of Qwen3.

---

## 11. Reproducibility

Every arm is a self-contained directory recording its rubric digest, corpus
digest, seed, served model and temperature in each result record, together with
the exact command that produces it. Total compute for every experiment in this
paper is a few GPU-hours on one consumer card; no API access is required.

Corpus digest `b60b2d62fbd0` (626 cases), gated by `scripts/validate_corpus.py`.
Prompt digests: generator `1de29ae28c7d`, v1 judge `1de29ae28c7d`, consensus judge
`b7f3b3ae1a5c`, both-versions diagnostic `1b4af11a652b`.

```bash
bash scripts/serve_qwen.sh
python3 experiments/2026-08-20_consensus-guard/run.py --generate --judge   # the method
python3 experiments/2026-08-18_rescue-arms/run_contrastive.py --mode generated
python3 experiments/2026-08-24_v2-rescue-rerun/report.py                   # -> report.md
```

---

## Appendix A — What did not work

Recorded because the negative results bound the claim, and because several are the
first thing a reader will propose. Rows marked *(PFA)* are on Paired Flag
Accuracy, chance **25%** (§4.3); they are not comparable to the 50%-chance
accuracies in §2.6 and §7.

| # | approach | outcome |
|---|---|---|
| 1 | A stronger generator | 15.4% → 16.0% *(PFA)*. No effect — consistent with §2.2. |
| 2 | More context for the generator | Negative. |
| 3 | A perfect reconstruction | The genuine patched function with locals renamed scores 14.6% against v1's 16.0% *(PFA)*. Reconstruction fidelity was never the constraint — §2.2. |
| 4 | Broad 5-way rubric with one reconstruction (v1) | At chance. The categories are dominated by the gap between *any* reconstruction and *either* real version, which swamps the difference between the two real versions. |
| 5 | Direct prompting ("is this function vulnerable?") | 6.9% *(PFA)*, 0.514 AUC; 7.2% with the specification supplied. Worse than v1. |
| 6 | A static analyser (flawfinder 2.0.20) | 2.8% *(PFA)*. Caveat: bare functions with no headers, macros or types, so its pattern rules mostly find nothing. |
| 7 | Predicting success from lexical specification overlap | Did not stratify the outcome. 47.7% of specs mention none of the identifiers that differ between the two versions, but accuracy does not vary with coverage. |
| 8 | Predicting success from fix category | 67.9% on a 28-case interim subgroup → 54.7% on the full sample. |
| 9 | A net-exposure decision rule, discovered on v2 data | p = 0.030 on the data that suggested it → p = 0.949 on independent v2-era data. *(It does hold for v3 — §7.2 — but it is reported there as a secondary operating point, not a headline.)* |
| 10 | A defensive generator instruction | 57.1% (p = 0.045) → 53.3% (p = 0.351) on a second seed. |

Two lessons carried into the present design. **Marginal single-run significance
failed to replicate twice** (#9, #10), which is why §7.1 is held as provisional
until its own replication returns. And **pre-registration is what made those
failures interpretable** — both were recorded with their predictions before the
deciding run, so the outcome could not be reinterpreted after the fact. The same
discipline is why §7.1 leads with the 539-case subset the analysis plan named in
advance, rather than the larger set available afterwards.
