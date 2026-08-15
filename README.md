# Unsupervised Vulnerability Detection by Specification Reconstruction

Noam Cohen, Shir Bernstein, Shir Rozenfeld, Tiltan Doron Gilat
Ben-Gurion University of the Negev — *Methods for Detecting Attacks*

Can a vulnerability be found without labels, without training, and without any
prior description of the vulnerability — using only the function's own
documentation?

A language model that has never seen the code writes implementations from the
docstring alone. A second model is shown one version of the real function at a
time, never told which version it is, and asked which defensive steps the
reconstructions perform that this version omits. Whichever version is rated
more exposed is called the vulnerable one.

On 626 CVE fix-pairs spanning 453 CVEs, this reaches **66.8%** where chance is
50%, with no supervised signal at any step.

---

## The method

### Stage 1 — Reconstruction

The generator receives exactly `{language, docstring}` and writes an
implementation. It never sees the real code, the CVE identifier, the
repository, or the commit message. **Five independent samples** are drawn at
temperature 0.8.

### Stage 2 — Judgement

The judge receives the specification, the five reconstructions, and **one**
version of the real function — the *target*. It is asked a narrow, non-lexical
question:

> Which defensive steps does the reconstruction perform that the target does not?

with "defensive step" enumerated concretely: a bounds or length check before an
access, a null or error-return check before use, an arithmetic overflow guard,
an initialisation before use, a lifetime step (free, unlock, refcount), input
validation, a permission check, an explicit bound on work or memory. It returns
an **exposure score** on 0–10.

The rubric also states what is *not* a difference — naming, types, helper
functions, control-flow shape, error-handling style, formatting, length — and
requires the same effect achieved differently (`if (n > max) return -EINVAL`
versus `n = MIN(n, max)`) to count as the same step.

### Stage 3 — Comparison

The harness runs stage 2 twice per case: once with the pre-patch version as
target, once with the post-patch version. The judge is never told which is
which, and the two calls are independent. **Whichever version received the
higher exposure score is called the vulnerable one.**

### Why five reconstructions and not one

A single from-spec reconstruction is genuinely *less* defensive than mature
production code, so comparing real kernel code against one sample usually finds
nothing and scores 0 on both sides. A single sample also cannot distinguish its
own arbitrary choices from what the specification requires.

Requiring a **majority** separates the two: a defensive step four of five
independent implementers take is a property of the specification, a step only
one takes is sampling noise. All five go into a single judge call, so the judge
applies the majority rule with the evidence in front of it and the cost stays
at two judge calls per case rather than ten.

---

## The three constraints

These are what make the result meaningful rather than circular.

1. **Information isolation.** The generator sees only `{language, docstring}`.
   Enforced structurally — the request body is built from those two fields, and
   `FORBIDDEN_IN_GENERATOR` in `method/run.py` asserts at run time that no
   snippet, CVE identifier, summary or commit message reached it.
2. **One version at a time.** The judge compares against a single version and is
   never told which it is, or that a vulnerability is involved. This is also a
   defence, not only a cost: a detector shown both versions at once can exploit
   the fact that security patches usually add lines, and the single-version
   formulation is structurally immune to a shortcut that lives in the
   comparison.
3. **No supervised signal.** The vulnerable/patched pairing exists only in the
   evaluation harness. The detector never sees a label.

---

## How accuracy is defined

The unit of measurement is a **pair**, not a function. Every case gives two
versions of the same function, before and after the security patch. We know
which is which; the detector does not.

| outcome | counted as |
|---|---|
| vulnerable version scored **higher** | correct |
| vulnerable version scored **lower** | wrong |
| the two scores are **equal** | undecided |

**Accuracy is the fraction of *decided* cases ranked correctly, and chance is
exactly 50%** — every case has one vulnerable and one patched version by
construction, so there is no class imbalance to correct for and no way to move
the baseline by flagging more or less often.

**Coverage** is the fraction of cases that are decided. Ties are reported as
coverage and are never counted as successes or failures; scoring them either
way would let us choose the headline. Accuracy is therefore conditional on
answering.

Confidence intervals are **CVE-clustered bootstraps** (10,000 resamples of
whole CVEs, not cases) because one CVE commit often patches several functions
and those cases succeed or fail together. The p-value is an exact two-sided
binomial test against 50%.

---

## Results

Qwen3-32B-AWQ in both roles, served locally by vLLM on one RTX 4090. Seed 1234,
generator temperature 0.8, judge temperature 0.0, K = 5. All figures below are
regenerated by `method/report.py`.

| set | cases | decided | coverage | accuracy | 95% CI | p vs 50% |
|---|---:|---:|---:|---:|---|---:|
| **539 non-duplicate (primary)** | 539 | 205 | 38.0% | **66.8%** | [60.4%, 73.3%] | 1.6 × 10⁻⁶ |
| 626 all cases (descriptive) | 626 | 236 | 37.7% | 65.3% | [59.1%, 71.4%] | 3.2 × 10⁻⁶ |

Of the 205 pairs the method was willing to rank, it put the vulnerable version
on top 137 times. The 87 `duplicate_of` cases — the same function reached
through more than one CVE record — are excluded from the primary set, which was
named as primary in advance.

**A second operating point.** The rubric also records the reverse comparison,
`consensus_exposure`. Differencing the two removes the offset common to both
judge calls and decides substantially more cases:

| decision rule | decided | coverage | accuracy | 95% CI |
|---|---:|---:|---:|---|
| target exposure | 236 | 37.7% | **65.3%** | [59.1%, 71.4%] |
| net exposure (target − consensus) | 344 | **55.0%** | 59.0% | [53.8%, 64.2%] |

Both exclude chance, so the method is tunable across a real coverage–accuracy
frontier: 17 points of coverage cost 6 points of accuracy.

### The control that matters

Security patches usually *add* lines, so *"the shorter version is the
vulnerable one"* is a rule needing no intelligence at all — and on this corpus
it is right on 86.8% of the pairs where it applies. If the method were secretly
ranking by length it would collapse where that shortcut is unavailable.

| stratum | decided | accuracy | 95% CI |
|---|---:|---:|---|
| vulnerable side shorter | 154 | 66.9% | [59.1%, 74.5%] |
| **equal length — no length signal** | 54 | **68.5%** | [56.2%, 80.8%] |
| vulnerable side longer | 28 | 50.0% | [30.0%, 69.2%] |

The method is flat across the strata and at its best where the shortcut is
gone. It picks the shorter side on 64.3% of unequal decided pairs — close to
what a length-blind detector at this accuracy would produce by chance.

We suggest the equal-length stratum as a standard control for any paired
evaluation on CVE fix-pairs.

### Other controls

- **Docstring leakage.** 32 of 626 cases carry a heuristic flag for docstring
  text that may describe the fix. Removing them changes nothing: 64.9% on the
  594 unflagged cases against 65.3% overall.
- **Corpus validation.** Every case is checked against `D.zip` before use, and
  the corpus is content-addressed, so no result can be produced against an
  unvalidated corpus.
- **Digest pinning.** Each result record carries `prompt_sha` and the served
  model, so no run can silently drift from the rubric it claims to use.

### Where the coverage goes

The rubric asks for 0–10 but binds ranges to severity classes, and the judge
answers at the class rather than within it: **92% of all scores are exactly 0,
4 or 6**. Two versions of the same function usually land in the same class, and
when they do the case ties — 62.3% of cases do. Coverage is a property of a
rubric that quantises to three levels, not of the idea, and a score decoupled
from the severity class is the most direct route to raising it.

---

## Data

`D.zip` contains 553 CVE fix commits. `scripts/extract_v2.py` turns them into
792 function-level records in `cases/`, each one function in two versions with
a structured docstring (Summary, Parameters, Returns, Logic).

| | |
|---|---:|
| records extracted | 792 |
| **usable** (`extraction_status: "ok"`) | **626** |
| non-duplicate (evaluation subset) | 539 |
| unique CVEs | 453 |
| languages | 595 C, 31 C++ |

`corpus_sha` `b60b2d62fbd0`. Repositories: `torvalds/linux` 337, ImageMagick
47, chromium 45, FFmpeg 15, krb5 12, radare2 9, others. Because 54% of cases
come from one repository, every interval is CVE-clustered rather than
case-level.

Records that cannot be posed as a reconstruction task — a patched line at file
scope, a `#define` macro with a statement-expression body, a function renamed
by the patch — are kept with an `extraction_status` explaining why rather than
deleted, so the exclusion is auditable.

---

## Running it

Requires Python 3.10+ (standard library only) and a vLLM server. `serve_qwen.sh`
hardcodes this machine's paths — edit `PY`, `MODEL_PATH` and `SERVED_NAME` at
the top for another environment.

```bash
bash scripts/serve_qwen.sh                      # local vLLM, ~4 min warmup

python3 scripts/validate_corpus.py              # gate: 626 usable, all checks pass
python3 scripts/corpus_sha.py                   # -> b60b2d62fbd0

python3 method/run.py --stage generate --k 5    # 5 reconstructions per case
python3 method/run.py --stage judge             # 2 judge calls per case
python3 method/report.py                        # -> method/report.md
```

A full pass over 626 cases at K = 5 takes a few GPU-hours on one consumer card.
Both stages are resumable — they skip cases already on disk — so an interrupted
run continues with the same command. No API access and no API costs.

To rebuild the corpus from the archive:

```bash
python3 scripts/extract_v2.py                   # D.zip -> cases/
```

---

## Layout

```
cases/                        the corpus: 792 records, 626 usable
D.zip                         source archive, 553 CVE fix commits
.claude/agents/
  vuln-generator.md           generator system prompt (specification only)
  vuln-judge.md               first-iteration judge, kept so prompt_sha reproduces
method/
  run.py                      stages 1-3: --stage generate | judge
  report.py                   every reported figure, from one results directory
  prompts/judge_consensus.md  the consensus rubric
  vllm_client.py              transport; grammar-constrained JSON decoding
  data.py                     corpus and result loaders
  paired_eval.py              directional accuracy, clustered bootstrap, binomial test
scripts/
  serve_qwen.sh               local vLLM bring-up
  extract_v2.py               D.zip -> cases/
  extract_cases.py            brace-matching helpers (library, no entry point)
  validate_corpus.py          the validation gate
  corpus_sha.py               corpus content addressing
  agent_prompts.py            prompt loading and digests
```

`method/run.py` writes to `method/candidates/` and `method/results/<run>/`;
both are gitignored and regenerable.

---

## Limitations

**Coverage is 38%.** The method answers on 205 of 539 cases, and the reported
accuracy is conditional on answering. A deployment would need to know whether
the abstention region is benign or systematically conceals a vulnerability
class. We have not characterised it.

**The anti-length stratum is underpowered.** 28 cases at 50.0%, CI [30.0%,
69.2%] — consistent with the 68.5% equal-length result and with chance alike.

**One model family.** Qwen3-32B in both roles. Generator and judge share
pretraining, and the design does not exclude correlation arising from that.

**One dataset, dominated by one repository.** 54% of cases are Linux kernel
code. CVE clustering corrects the variance estimate, not the composition.

**The specifications were written alongside the pre-patch code.** Identifiers
unique to the pre-patch version appear in the docstrings 3.7× more often than
patched-only identifiers. This biases *against* the method — a faithful
reconstruction from such a specification should resemble the vulnerable version
— so the reported accuracy is if anything understated.

**Scope.** C and C++, predominantly memory-safety and input-validation CVEs.
Nothing here speaks to logic flaws, race conditions, or managed-language
vulnerabilities.

**Ties are excluded, not resolved.** Reporting accuracy on the decided subset
is the honest choice available, but it means the method's behaviour on 62% of
cases is described only by its coverage.
