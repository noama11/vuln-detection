# WP-next — corrected extraction (`extraction-v2`)

**Objective**: close `RESEARCH_LOG.md` open thread #4 — *"fix the extraction
defect and re-derive the corpus; the ~49% clean rate is optimistic"*.

Additive arm. `scripts/`, `cases/`, `results/`, `reports/`, `pilot/` and
`.claude/` are unmodified; every published arm stays byte-reproducible.
No inference was run — this arm produces a corpus and an audit, nothing more.

## 1. The published corpus is worse than §5.2 records

`FINDINGS.md` §5.2 measures the vulnerable-side defect by **brace balance** and
reports 111/392 (28.3%) malformed. That test undercounts: the
dominant failure is the slice running *past* the target function into the next
one, and the trailing fragment frequently happens to balance. `C_276__0` carries
`vfs_rename` + `EXPORT_SYMBOL` + the head of `SYSCALL_DEFINE5` at balance 0.

Re-measured with the strict test — exactly one complete top-level function,
nothing glued on after its closing brace:

| The 392 `ok` vulnerable snippets | n | |
|---|---:|---:|
| target function **+ fragment of the next function** | 197 | 50% |
| clean single function | 163 | 42% |
| no complete function (truncated or body-only) | 31 | 8% |
| body only, no signature | 1 | 0% |
| **defective** | **229** | **58%** |

The fixed side of the same cases is 390/392 (99.5%) clean, because it is
brace-matched rather than sliced. **That asymmetry is the defect**: every
published metric compared each candidate against a clean post-patch reference
and a contaminated pre-patch one.

Separately, 7 of the 392 are `#define` macros with statement-expression
bodies rather than functions, so there is no function to reconstruct from a
docstring at all.

## 2. Three bugs in `scripts/extract_cases.py`

**B1 — the fixed side extracts an inner block, not the function.**
`locate_function_by_anchor` (`scripts/extract_cases.py:151`) selects the
*innermost* brace pair containing the anchor. When the patched line sits inside
an `if`/`while`, that returns the loop body: `C_435__0` extracted
`if (pkt->size >= 7 && …` instead of `read_gab2_sub`. The innermost choice was
guarding against C++ `namespace`/`class` wrapping, but it overshoots on every
nested statement. This is the whole `suspect_identifier_mismatch` class — the
right function was located all along, then discarded by the identifier check.

**B2 — the vulnerable side is sliced literally from `scope.start`/`scope.end`**
(`scripts/extract_cases.py:239`) while the fixed side is brace-matched. Those
ranges are frequently not function boundaries — `D/C/1222` has `scope.start = 131`,
a statement-continuation line deep inside a body — so the slice over-runs into
the following function.

**B3 — the multi-function guard has a blind spot.** `count_top_level_braces`
(`scripts/extract_cases.py:137`) counts only *matched* brace pairs, so a slice
ending in an unclosed `{` is never flagged. That is exactly what B2 produces,
and it is why contaminated cases carry `extraction_status: "ok"`.

`extract_v2.py` fixes all three: `locate_enclosing_function` walks
outermost-inward and skips wrapper constructs explicitly; both sides are
anchored on the matched `changed_lines` hunk and brace-matched identically, so
the scope range is a hint and never a boundary; and `is_single_clean_function`
additionally requires that nothing follows the closing brace.

## 3. Funnel

| Stage | n |
|---|---:|
| scope entries in `D.zip` | 792 |
| − changed lines not fully inside the located function | 91 |
| − patched line is at file scope (include block, global, class body) | 35 |
| − no `changed_lines` entry overlaps the scope range | 25 |
| − `#define` macro with a statement-expression body, not a function | 13 |
| − function absent from the fixed side (renamed or deleted by the patch) | 2 |
| **usable** | **626** |

626 cases, 539 unique functions. The remaining 87 are the same
function emitted twice because the dataset generated two docstrings for it
(`D/C/1222` scope 0 and 1 share range 131–204). Both are kept and flagged with
`duplicate_of`, so a metric can drop them without losing the docstring-variant
signal.

### Transition from the published extractor

| published status | | n |
|---|---|---:|
| `ok` | kept | 344 |
| `suspect_identifier_mismatch` | kept | 195 |
| `unsupported_multi_function_scope` | kept | 85 |
| `unsupported_multi_function_scope` | dropped | 64 |
| `ok` | dropped | 48 |
| `skipped` | dropped | 31 |
| `suspect_identifier_mismatch` | dropped | 23 |
| `skipped` | kept | 2 |

**344 of the published 392 survive; 48 do not**, because:

- 30 — changed lines not fully inside the located function
- 9 — patched line is at file scope (include block, global, class body)
- 7 — `#define` macro with a statement-expression body, not a function
- 2 — function absent from the fixed side (renamed or deleted by the patch)

## 4. Does the defect explain the null?

Reproduced from `results/qwen_full/` in place: n_scored = 357, 
PFA = 0.1597 — matching `reports/qwen_full_report.md` exactly, which
confirms the loader path is equivalent before any split is reported.

| defective set | defective ref | clean ref | z | p |
|---|---|---|---:|---:|
| any defect | 16.7% (n=203) | 14.9% (n=154) | +0.46 | 0.643 |
| over-extension only | 14.4% (n=181) | 17.6% (n=176) | -0.84 | 0.402 |

**No.** The two slices disagree on sign and neither is significant, consistent
with §5.2's own 16.0% → 15.8% check. The corrected corpus buys credibility and
statistical power, not a different headline. Any re-run should be framed that
way in the paper.

## 5. The v2 corpus

| | published | v2 |
|---|---:|---:|
| usable cases | 392 extracted / 357 scored | **626** |
| vulnerable side a single complete function | 163 | 626 |
| unique functions | — | 539 |
| unique CVEs | 302 | 453 |
| 95% CI half-width at PFA≈16% | ±3.8% | ±2.9% |
| largest repo share | 51% | 54% |

Composition: `torvalds/linux` 337, `ImageMagick/ImageMagick` 47, `chromium/chromium` 45, `FFmpeg/FFmpeg` 15, `krb5/krb5` 12.
Languages: {'c': 595, 'cpp': 31}.

**Repo clustering does not improve** — `torvalds/linux` still dominates — so
`FINDINGS.md:157`'s CVE-clustered bootstrap CIs remain the right choice.

## 6. Verification

| check | result |
|---|---|
| `extract_v2.py` run twice, `diff -r` on the output | identical |
| in-script `is_single_clean_function` assertion on every emitted case | 626/626 |
| `spot_check.py` — snippets are verbatim substrings of `D.zip` | 626/626 |
| `spot_check.py` — recorded line ranges agree with the snippets | pass |
| `spot_check.py` — same function identifier on both sides | pass |
| `spot_check.py` — vulnerable and fixed differ; docstring present | pass |
| `audit_current.py` reproduces `n_scored`=357 and PFA=0.1597 | pass |
| `git status` — writes confined to this arm directory | pass |

Manual reading of sampled diffs (`spot_check.py --show 4`) confirms the
recovered pairs are genuine CVE fixes: `C_560__0` adds the missing bounds check
before `CopyMagickMemory` (CVE-2016-7538), `C_179__0` adds `memset(&line, 0, …)`
against an infoleak (CVE-2014-1445), `C_160__2` threads the extra
`__load_segment_descriptor` argument (CVE-2014-3647).

## 7. Known follow-up

`scripts/run_cases_local.py:35` hardcodes `CASES_DIR = ROOT / "cases"` with no
override flag, so running inference on `cases_v2/` needs either a `--cases-dir`
flag (touches `scripts/`, breaking additivity) or a thin runner inside this arm.
Worth deciding once the corpus is approved.
