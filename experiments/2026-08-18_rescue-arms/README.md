# WP5 — Rescue arms: the contrastive judge

**Objective**: attack the mechanism WP1's permutation test identified. The
published method asks two independent questions that share the candidate and
differ only in the reference, and the reference barely enters the verdict. This
arm asks **one** question with **both** references present, in randomised order,
narrowed to a single predicate: *does one side omit a defensive step the other
performs?*

**What differs from the reference arm**: a new rubric
(`prompts/judge_contrastive.md`), so this arm carries its own `prompt_sha` and
deliberately does **not** match the published `1de29ae28c7d`. The published agent
files are untouched. `neither` is a permitted answer, scored as an abstention and
reported separately, so accuracy cannot be inflated by forcing guesses.

**Rerun**:

```bash
bash scripts/serve_qwen.sh
python3 experiments/2026-08-18_rescue-arms/run_contrastive.py --mode oracle
python3 experiments/2026-08-18_rescue-arms/run_contrastive.py --mode generated
python3 experiments/2026-08-18_rescue-arms/report.py
```

~5–6 min per mode (one call per case instead of two).

## Result

| Mode | decided | accuracy | 95% CI | abstained |
|---|---|---|---|---|
| oracle — A/B are the two real snippets | 308/391 | **84.4%** | [80.1%, 88.4%] | 21.2% |
| generated — same, plus the reconstruction as context | 325/391 | 81.5% | [77.2%, 85.8%] | 16.9% |

Chance is 50%. Exact binomial: **p < 1.1×10⁻³⁶**. CIs are CVE-clustered
bootstraps.

## Artefact checks — both pass

This corpus has two defects that could manufacture a high score, so neither
number is reportable without ruling them out:

| Check | Result | Reading |
|---|---|---|
| Extraction defect (28.3% of vulnerable snippets malformed) | clean 84.8%, malformed 83.7% | no effect |
| Length (`longer side is vulnerable` reaches 21.4% PFA) | equal-length **89.0%**, unequal 66.7% | *opposite* of a length heuristic |
| Position | always-A scores 47.6% | order randomised per case from a seeded hash of the case id |

Accuracy being **highest** on equal-length pairs — where line count carries zero
information — is the strongest single piece of evidence that the result is
semantic rather than superficial.

## What this shows

The same model, same weights, same corpus, at 84% against a 50% baseline. **The
information needed to separate a pre-patch from a post-patch function is present
in this data, and Qwen3-32B can extract it.** The published method's 16% is
therefore a property of the task formulation — two independent judgements, a
5-way taxonomy, a metric requiring one specific category — and not of the model,
the corpus, or the difficulty of the underlying problem.

Supplying the reconstruction as context changes almost nothing (81.5% vs 84.4%),
which corroborates WP2: the reconstruction is not where the value is.

## What this does NOT show — put this in the paper

The contrastive arm is **not a deployable detector**. It requires *both* the pre-
and post-patch versions of the function, which is exactly what a real detector
does not have — at detection time only one version exists. It is a diagnostic and
an upper bound, not a method. Presenting it as a working vulnerability detector
would be wrong, and a reviewer will catch it.

The honest framing: the contrastive result establishes the ceiling the
single-version problem must be measured against. **The gap between 84% (both
versions, right question) and 16% (one version reconstructed from a spec, wrong
question) is the quantified cost of the formulation.**

## The obvious follow-up

Ask the *contrastive* question with the reconstruction as the compared side
rather than as passive context — i.e. "does the reference omit a defensive step
the reconstruction performs?" That would be single-version and therefore
deployable. It is one run away and is the highest-value experiment left after
WP4(b).
