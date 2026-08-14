# WP5 — The contrastive judge

The published method asks two independent questions that share the candidate and differ only in the reference; WP1's permutation test shows the reference barely enters the verdict. This arm asks **one** question with **both** references present in randomised order, narrowed to a single predicate: *does one side omit a defensive step the other performs?*

`neither` is a permitted answer, scored as an abstention and reported separately, so accuracy cannot be inflated by forcing guesses.

| Mode | n | decided | accuracy (decided) | 95% CI | accuracy (all) | abstained | chance |
|---|---|---|---|---|---|---|---|
| **oracle** | 391 | 308 | **84.4%** | [80.1%, 88.4%] | 66.5% | 21.2% | 50.0% |
| **generated** | 391 | 325 | **81.5%** | [77.2%, 85.8%] | 67.8% | 16.9% | 50.0% |

Exact binomial test against chance: 260/308, **p < 1.1e-36**.

## Artefact checks

Two known defects in this corpus could produce a high score without any semantic ability: the 28.3% vulnerable-side extraction defect (`experiments/2026-08-17_spec-provenance/`), and the length asymmetry that lets `longer side is vulnerable` reach 21.4% PFA (`experiments/2026-08-16_baselines/`). Both are ruled out.

**oracle**

| stratum | n | accuracy |
|---|---|---|
| clean | 210 | 84.8% |
| malformed | 98 | 83.7% |
| equal length | 245 | 89.0% |
| vulnerable longer | 51 | 66.7% |
| vulnerable shorter | 12 | 66.7% |

**generated**

| stratum | n | accuracy |
|---|---|---|
| clean | 220 | 81.8% |
| malformed | 105 | 81.0% |
| equal length | 253 | 85.4% |
| vulnerable longer | 59 | 67.8% |
| vulnerable shorter | 13 | 69.2% |

**Extraction defect**: accuracy is the same on cleanly extracted and malformed cases. The judge is not keying on the trailing garbage that over-running vulnerable snippets carry.

**Length**: accuracy is *highest* on equal-length pairs — where line count carries no information at all — and drops where the lengths differ. That is the opposite of what a length heuristic would produce.

**Position bias**: answers {'A': 164, 'neither': 83, 'B': 144} against true labels {'A': 186, 'B': 205}. An always-A strategy would score 47.6%, far below the observed accuracy, so the result is not an artefact of label placement (order is randomised per case from a seeded hash of the case id).

## Does the reconstruction help?

oracle 84.4% vs generated 81.5% — supplying the spec-reconstruction candidate as extra context changes little (-2.9%). The signal comes from the direct comparison of the two versions, not from the reconstruction. This is consistent with WP2: reconstruction is not where the value is.

## What this does and does not show

**Does show.** The same model, the same weights, the same corpus, at 84% against a 50% baseline, p < 1e-30. The information needed to separate a pre-patch from a post-patch function *is present in this data*, and Qwen3-32B *can extract it*. The published method's 16% is therefore a property of the **task formulation** — two independent judgements, a 5-way taxonomy, and a metric requiring one specific category — and not of the model, the corpus, or the difficulty of the underlying problem. That is the missing piece of the negative result: it converts *"this does not work"* into *"this does not work, and here is proof that the failure is in the formulation rather than the data."*

**Does not show — state this plainly in the paper.** The contrastive arm is **not a deployable detector**. It requires *both* the pre- and post-patch versions of the function, which is exactly what a real detector does not have: at detection time only one version exists. It is a diagnostic and an upper bound, not a method. Presenting it as a working vulnerability detector would be wrong, and a reviewer will catch it.

**The honest framing**: the contrastive result establishes the ceiling that the single-version problem must be measured against. The gap between 84% (both versions, right question) and 16% (one version reconstructed from a spec, wrong question) is the paper's quantified statement of how much the formulation costs.

