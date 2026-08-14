# WP4 — Specification provenance

**Objective**: test whether the corpus's specifications are derived from the
*vulnerable* version of each function. If they are, a faithful clean-room
reconstruction should resemble the vulnerable code, and the detector is biased
against its own hypothesis by construction.

**What differs from the reference arm**: part (a) is pure computation over
`cases/*.json`, read-only. Part (b) regenerates specifications from the fixed
snippet and re-runs the published method against them — writing to this arm's own
`cases_fixed_spec/`. **`cases/*.json` is never modified**, unlike the earlier
`scripts/apply_docstring_fixes.py` pass which rewrote docstrings in place.

**Rerun**:

```bash
python3 experiments/2026-08-17_spec-provenance/analyze.py               # (a), no GPU

bash scripts/serve_qwen.sh                                             # (b)
python3 experiments/2026-08-17_spec-provenance/respec.py --stage respec --limit 150
python3 experiments/2026-08-17_spec-provenance/respec.py --stage run
```

## (a) Findings — done

**The specifications are derived from the vulnerable code.** Counting
identifiers unique to one side of the fix against the docstring:

| | mentions | cases leaning this way |
|---|---|---|
| vulnerable-only | **470** | 94 |
| fixed-only | **127** | 41 |

3.7× asymmetry; sign test **p = 2.9×10⁻⁶** over the 135 non-tied cases. The
corpus structure corroborates it: `D.zip`'s `scope` entries carry `start`/`end`
line numbers into `vulnerable.<ext>`, so the documentation was generated against
the pre-patch file.

This **survives the `HANDOFF.md` §3 leakage audit**, which removed docstrings
that state the fix or narrate the bug. It could not remove the fact that the spec
was written by reading the vulnerable function. It predicts the two anomalies the
write-up reports without explaining: ROC-AUC 0.475 (below chance) and a −0.18
score gap favouring the vulnerable side.

**This is not only a dataset artefact.** In deployment a project's docstring is
written alongside the code it documents — the vulnerable version, right up until
the patch lands. Any spec-reconstruction detector inherits this bias wherever the
spec is not authored independently of the implementation. Put it in the paper as
a design constraint on the method family, not merely as a threat to this corpus.

**An undocumented extraction defect** (found while building this, mirror of
`PILOT_INSIGHTS.md` Finding 1): `extract_cases.py` slices the vulnerable snippet
from the dataset's literal `scope.start`/`scope.end` range, which over-runs the
target function in 93/392 cases and truncates in 18 more.

| Side | balanced | malformed |
|---|---|---|
| vulnerable | 281 | **111 (28.3%)** |
| fixed | 389 | 3 (0.8%) |

All carry `extraction_status: "ok"`. It does **not** explain the null (PFA
16.0% → 15.8% on clean cases) but it belongs in Threats and it biases every
length-correlated comparison.

**A lower bound on spec sufficiency**: 47.7% of cases mention *none* of the
identifiers that differ between versions; median coverage 4.3%. Motivating, but
see the negative result in `experiments/FINDINGS.md` §7 — stratifying by this
proxy does not separate the strata, so it cannot carry the claim on its own.

## (b) The causal test — script ready, not yet run

Regenerate each spec from the **fixed** snippet, then re-run the method.

- **If the sign flips** (score gap turns positive, AUC crosses 0.5): provenance
  is causal, and the paper can state that *the direction of the detector's bias
  is set by the provenance of the specification* — a transferable claim.
- **If nothing moves**: provenance is exonerated and the information-deficit
  account stands alone.

Both outcomes are reportable, which is why this is worth running.

Design notes: the subset is stratified at one case per CVE so correlated
multi-function commits do not inflate the effective sample; the regenerated specs
pass a ≥25-character shared-line leakage gate against both snippets (the same
check the published arm's §7 describes); and `--gen-max-tokens` defaults to 4096
here rather than the published 2048, which truncated four candidates.
