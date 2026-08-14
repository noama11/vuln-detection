# WP-next — corrected extraction (`extraction-v2`)

**Objective**: close `RESEARCH_LOG.md` open thread #4 — *"fix the extraction
defect and re-derive the corpus; the ~49% clean rate is optimistic"*.

It is worse than optimistic. `FINDINGS.md` §5.2 measures the vulnerable-side
defect by brace balance and reports 28.3%; measured strictly — exactly one
complete function, nothing glued on — it is **58%**. The published extractor
also discards 400 of 792 scope entries, most of which are recoverable.

| | published | v2 |
|---|---:|---:|
| usable cases | 392 extracted / 357 scored | **626** |
| vulnerable side a single complete function | 163 | 626 |
| unique CVEs | 302 | 453 |
| 95% CI half-width at PFA≈16% | ±3.8pp | ±2.9pp |

**This does not overturn the null.** Splitting the published run by reference
quality gives p = 0.64 / p = 0.40 depending on how "defective" is drawn, with
the two slices disagreeing on sign — consistent with §5.2's own 16.0% → 15.8%
check. The corrected corpus buys credibility and power, not a different
headline. See `report.md` §4.

Additive arm: `scripts/`, `cases/`, `results/`, `reports/`, `pilot/` and
`.claude/` are unmodified, so every published arm stays byte-reproducible.
**No inference was run.**

## The three bugs

| | in `scripts/extract_cases.py` | effect |
|---|---|---|
| B1 | `locate_function_by_anchor:151` takes the **innermost** enclosing brace pair | returns the `if`/`while` block the patched line sits in, not the function — the entire `suspect_identifier_mismatch` class |
| B2 | the vulnerable side is sliced **literally** from `scope.start`/`scope.end` (`:239`) while the fixed side is brace-matched | the slice over-runs into the following function; `scope.start` is often not a function boundary at all |
| B3 | `count_top_level_braces:137` counts only **matched** brace pairs | a slice ending in an unclosed `{` is never flagged — which is exactly what B2 produces, so contaminated cases carry `extraction_status: "ok"` |

`extract_v2.py` walks enclosing pairs outermost-inward while skipping wrapper
constructs (B1), anchors and brace-matches both sides identically so the scope
range is a hint and never a boundary (B2), and requires that nothing follows the
function's closing brace (B3). It also drops `#define` macros with
statement-expression bodies, which present as functions but cannot be
reconstructed from a docstring — 7 of the published 392 are these.

## Rerun

```bash
python3 experiments/2026-08-22_extraction-v2/extract_v2.py     # -> cases_v2/ (~20s, no GPU)
python3 experiments/2026-08-22_extraction-v2/spot_check.py     # structural checks over all 626
python3 experiments/2026-08-22_extraction-v2/audit_current.py  # defect rate + PFA split
python3 experiments/2026-08-22_extraction-v2/report.py         # -> report.md
```

`spot_check.py --show 4` prints unified diffs of sampled recovered cases for
reading by eye.

## Output

`cases_v2/` holds all 792 scope entries with a status, mirroring the published
extractor so the file set is a complete audit trail and `run_cases_local.py`
(which selects on `extraction_status == "ok"`) can consume it unchanged. Schema
is the published case schema plus:

- `duplicate_of` — 87 cases are the same function emitted twice because the
  dataset generated two docstrings for it (`D/C/1222` scope 0 and 1 share range
  131–204). Both are kept so the docstring-variant signal survives; drop them at
  metrics time if independence matters. 539 unique functions.
- `func_name`, `anchor_strategy`, `extraction_method` — for auditability.
- `scope_line_range` — the dataset's original range, retained for comparison
  now that it no longer determines the snippet.

## Caveats

- **Repo clustering does not improve.** `torvalds/linux` is 54% of v2 vs 51% of
  the published corpus, so `FINDINGS.md:157`'s CVE-clustered bootstrap CIs
  remain the right choice.
- **48 of the published 392 do not survive** — 30 have changed lines outside the
  located function, 9 patch file scope, 7 are macros, 2 lose the function on the
  fixed side. Each is a case the method cannot pose, not a case the new
  extractor failed on.
- **`run_cases_local.py:35` hardcodes `CASES_DIR = ROOT / "cases"`** with no
  override. Running inference on `cases_v2/` needs either a `--cases-dir` flag
  (touches `scripts/`, breaking additivity) or a thin runner in this arm.
