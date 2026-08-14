# WP4(a) — Specification provenance, and an extraction defect

## 1. The specifications are derived from the vulnerable code

For each case, count how many identifiers unique to one side of the fix the docstring mentions. An identifier that appears only in the vulnerable version and also in the spec is information the spec could only have got from the vulnerable version.

| | Total mentions | Cases leaning this way |
|---|---|---|
| Vulnerable-only identifiers | **470** | **94** |
| Fixed-only identifiers | **127** | **41** |
| (neither / tied) | — | 257 |

Ratio **3.7x** toward the vulnerable side. Sign test over the 135 non-tied cases: **p = 2.93e-06** one-sided.

This survives the docstring-leakage audit described in `HANDOFF.md` s3. That audit removed docstrings that *state the fix* or *narrate the bug*; it could not remove the fact that the spec was written by reading the pre-patch function. The corpus's own structure confirms the mechanism: `D.zip`'s `scope` entries carry `start`/`end` line numbers into `vulnerable.<ext>`, so the documentation was generated against the vulnerable file.

**Consequence for the method.** The method's premise is that a clean-room implementation written from a correct spec resembles *correct* code. If the spec is a description of the vulnerable code, the reconstruction should resemble the *vulnerable* code instead, and the detector is biased against its own hypothesis. This predicts exactly the two anomalies the write-up reports without explaining: ROC-AUC of 0.475 (below 0.5) and a mean score gap of -0.18 in favour of the vulnerable side.

**This is not only a dataset artefact.** In deployment the same thing holds: a real project's docstring is written alongside the code it documents, which is the vulnerable version right up until the patch lands. Any spec-reconstruction detector inherits this bias wherever the spec is not written independently of the implementation. WP4(b) tests the claim causally by regenerating specs from the fixed side and looking for a sign flip.

## 2. How much of the fix the spec could possibly describe

A lexical lower bound on spec sufficiency: what fraction of the identifiers that differ between the two versions does the docstring mention at all? If it mentions none of them, no reconstruction from that spec can distinguish the versions, whatever model writes it.

- Median coverage: **4.3%**
- p25 0.0%, p75 28.0%
- Cases mentioning **none** of the changed identifiers: **187/392** (47.7%)

This is a *lower* bound on the information deficit — a spec can describe a property without naming the identifiers involved — so WP4(c) re-measures it semantically. But it already shows the ceiling is well below 100%: for a large minority of the corpus the specification is silent about everything the patch touched.

## 3. An undocumented extraction defect on the vulnerable side

`PILOT_INSIGHTS.md` Finding 1 documents the *fixed*-side extractor landing on the wrong function. The vulnerable side has the mirror problem, and it is recorded nowhere: `extract_cases.py` slices the vulnerable snippet straight from the dataset's literal `scope.start`/`scope.end` line range, and that range frequently over-runs the target function.

| Side | brace-balanced | over-runs into next function | truncated |
|---|---|---|---|
| vulnerable | 281 | **93** | 18 |
| fixed | 389 | — | 3 |

**111 of 392 (28.3%) vulnerable snippets are malformed, against 3 (0.8%) on the fixed side.** Every one of these cases carries `extraction_status: "ok"`, so they are inside all published metrics.

Example, `C_102__0`: the vulnerable snippet ends part-way into `shmem_show_options`, the function following the target `shmem_remount_fs`; the fixed snippet ends correctly at the target's closing brace.

Effect on the published run:

| Vulnerable-side extraction | n scored | PFA | ROC-AUC | flag vuln / fixed |
|---|---|---|---|---|
| cleanly extracted | 260 | 15.8% | 0.480 | 41.5% / 41.9% |
| over-run | 85 | 15.3% | 0.450 | 38.8% / 50.6% |

**It is a genuine data-quality problem but not the cause of the null**: restricting to cleanly extracted cases barely moves PFA. It does inflate the fixed-side flag rate and depress ROC-AUC, and it biases any length-based comparison, so it belongs in Threats and should be fixed before anyone reuses this corpus.
