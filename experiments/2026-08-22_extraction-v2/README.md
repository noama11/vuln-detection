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
python3 scripts/validate_corpus.py --cases-dir experiments/2026-08-22_extraction-v2/cases_v2
python3 experiments/2026-08-22_extraction-v2/audit_current.py  # defect rate + PFA split
python3 experiments/2026-08-22_extraction-v2/report.py         # -> report.md
```

`spot_check.py --show 4` runs the same gate and then prints unified diffs of
sampled recovered cases for reading by eye.

## What this arm changed outside itself

The defect survived eight arms because `extraction_status: "ok"` was written by
the same code that had the bug, and the one validity check ever run — brace
balance — could not see the failure mode. Two project-level gaps followed from
that, and both are now closed in `scripts/`:

**`scripts/validate_corpus.py`** — structural validation independent of whatever
produced the corpus. Seven invariants, checked against the raw files in `D.zip`;
exit code 1 on any failure, so it works as a gate. Run it on any corpus before
trusting a number derived from it.

```
$ python3 scripts/validate_corpus.py                      # the published corpus
  [ok  ] snippet is a verbatim substring of D.zip     784/784
  [FAIL] recorded line range agrees with the snippet  771/784
  [FAIL] exactly one complete function per side       553/784
  [FAIL] not a preprocessor macro                     765/784
  [FAIL] same function identifier on both sides       326/392
329 FAILURES across 261 cases          CORPUS INVALID   (exit 1)

$ python3 scripts/validate_corpus.py --cases-dir .../cases_v2
all checks passed                                       (exit 0)
```

**261 of the published 392 cases (67%) fail at least one invariant.** The gate
also surfaced a defect neither the audit nor `FINDINGS.md` had recorded: on 13
cases the dataset's `scope` range runs past the end of the file (`C_591__0`
claims lines 771–803 of a 788-line file), and the literal slice clamps silently,
so the stored `vulnerable_line_range` describes more lines than the snippet holds.

**`scripts/corpus_sha.py`** — content-addresses a corpus the way
`agent_prompts.py` content-addresses the rubric. Every result already carried
`prompt_sha`; there was no equivalent for the corpus, so swapping `cases/`
changed every downstream figure with no trace in any artifact. That is precisely
why the eight published arms cannot say which corpus they ran against.

| corpus | ok cases | `corpus_sha` |
|---|---:|---|
| `cases/` | 392 | `d98dcc64782d` |
| `cases_v2/` | 626 | `b60b2d62fbd0` |

`run_cases_local.py` now takes `--cases-dir` and stamps `corpus_sha`,
`corpus_dir` and `corpus_n_ok` into every result record's `runtime` block,
alongside the existing `prompt_sha`. Defaults are unchanged — with no flag it
selects the same 392 cases from `cases/` as before, so this is additive to the
record schema and inert for reproduction of the published arms.

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
- **The additivity rule now cuts both ways.** Freezing `scripts/` and `cases/`
  kept the published arms byte-reproducible, and it is also why a known defect
  sat in the base for weeks with no path to being fixed. The resolution is to
  *version* the base rather than freeze it: tag the pre-change commit so
  everything published so far stays reproducible, then let `scripts/` move
  forward. `corpus_sha` is what makes that safe — a result now names the corpus
  it came from, so the two can no longer be silently confused.
