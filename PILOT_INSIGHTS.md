# Pilot Run — Insights (15/27 cases completed, run stalled on a usage limit)

**Bottom line up front: the current numbers are not trustworthy yet.** The
headline metrics look bad (9% Paired Flag Accuracy, 27% generation-failure
rate, ROC-AUC 0.52 — barely above chance), but root-causing the failures
shows most of them trace back to a **fixed-side snippet extraction bug**,
not to the Generator or Judge behaving badly. This needs fixing before the
pilot numbers mean anything.

**Batch status**: the run did not finish on its own — it hit the Claude Code
session usage limit partway through (error in the logs: "You've hit your
session limit · resets 1:40pm (Asia/Jerusalem)"). 12 of the remaining 12
cases failed both retry attempts for that reason, not a pipeline bug. The
batch driver is idempotent, so re-running `pwsh scripts/run_batch.ps1 -Run
pilot` after the reset time will pick up exactly the 12 missing cases.

## Raw numbers so far (from `scripts/compute_metrics.py pilot`)

| Metric | Value |
|---|---|
| Cases with results | 15 / 27 |
| Generation-failure rate (`degenerate_generation`) | 26.7% (4/15) |
| Paired Flag Accuracy (primary) | 9.1% (1/11 non-degenerate) |
| Pairwise Ranking Accuracy (secondary) | 18.2% (2/11) |
| ROC-AUC (diagnostic) | 0.52 (chance = 0.5) |
| Go/no-go call | **NO-GO** per pre-registered bands |

Don't read the "NO-GO" literally yet — see below.

## Finding 1 (root cause, high confidence): the extraction pipeline sometimes grabs the wrong thing from `fixed.<ext>`

All 4 `degenerate_generation` cases were checked by hand. In every one, the
Judge's "incoherent/off-topic" call was **correct given what it was shown**
— but what it was shown was wrong:

- **`C_142__0`**: the docstring describes `__udf_read_inode` /
  `UDF_MAX_ICB_NESTING`. The `fixed_snippet` we extracted is actually a
  completely different function, `udf_setsize`. The anchor-based locator
  landed in the wrong place in `fixed.<ext>`.
- **`C_812__0`**: the extracted `fixed_snippet` is a bare `while` loop
  fragment with no function signature at all — the innermost-enclosing-brace
  heuristic landed inside a nested block, not at the actual function's outer
  body.
- **`C_859__0`** and **`Cpp_732__0`**: the `scope` entry in the original
  dataset spans **multiple** functions/declarations (e.g. a struct plus
  several free functions), which the docstring describes collectively. Our
  vulnerable-side extraction handles this fine (it just slices the literal
  line range). Our fixed-side extraction does not — it's built to find *one*
  enclosing function via brace-matching, so it only grabs one piece of a
  multi-part scope, creating an apples-to-oranges comparison.

**Practical effect**: every one of these 4 cases is being scored (or
excluded) based on a broken comparison, not on genuine Generator/Judge
behavior. Since the "94% clean extraction" figure from `extract_cases.py`
only checked "did we find *some* enclosing function," not "is it the
*right* one," the true clean-extraction rate is lower than 94% — this pilot
is the first place that surfaced it, via the Judge noticing incoherence.

**Suspected mechanism worth testing next**: line-ending/offset drift. The
anchor line number comes from `changed_lines[...].fixed_lines.start`, and
character offsets are computed by cumulative Python-side line lengths. If
the dataset's original line numbers were computed under a different
line-ending assumption than Python's `splitlines()`, the anchor would drift
by a few lines — worse the deeper into a file — which would explain
"landed one function too early/nested one level too deep" better than pure
bad luck.

## Finding 2 (real, separate issue): the Generator's missing context creates a "baseline gap" that swamps the vulnerability signal

Looking at the 11 non-degenerate cases, **8 of them (73%)** have the
Judge assign the **same category** to both the vulnerable-side and
fixed-side comparison (both `equivalent_implementation_difference`, both
`functional_mismatch`, or both `security_vulnerability_concern`). That means
the specific difference between the vulnerable and fixed versions of a
function is often small **relative to** the difference between
Haiku's from-scratch reimplementation and either real version — because
Haiku never sees the project's real types, macros, or sibling functions,
so its output differs from *both* references in similar, unrelated ways.

Concretely, in the InspIRCd case reported earlier (`Cpp_270__0`), Haiku
simply dropped a `cap` parameter it didn't understand from a terse
description — a difference present against both the vulnerable and fixed
code, unrelated to the actual CVE, that ended up dominating the Judge's
verdict on both calls.

This is not a bug — it is a real property of using a cheap, zero-context
Generator model, and it's exactly the kind of thing the plan flagged as an
open question ("may need escalating Generator to Sonnet"). Distinguishing
this from Finding 1 matters: Finding 1 is a bug to fix; Finding 2 is a
modeling choice to test (e.g., pilot a Sonnet-generator subset once the
extraction bug is fixed, and compare).

## What this means for the go/no-go decision

**Recommendation: don't apply the pre-registered go/no-go bands to the
current numbers.** Fix the fixed-side extraction issue first (or at minimum,
add a validation check — e.g., does the extracted `fixed_snippet` contain an
identifier that also appears in the docstring/vulnerable_snippet? — and
exclude/flag cases that fail it), then re-run the pilot cases affected by
it before deciding go/no-go. The 10 non-degenerate cases may still be
informative about Finding 2, but 14/27 is too small to separate "Finding 2 is
just how it is" from "Finding 2 is partly extraction noise too."

## Suggested next steps (in order)

1. Resume the batch after the session limit resets (1:40pm Asia/Jerusalem)
   with `pwsh scripts/run_batch.ps1 -Run pilot` — it will only run the 12
   still-missing cases. More data points help characterize how widespread
   Finding 1 is.
2. Add a cheap sanity check to `extract_cases.py`: after locating the
   fixed-side function, verify it shares at least one identifier (function
   name, or a distinctive token) with the vulnerable-side snippet; if not,
   mark `extraction_status: "suspect"` instead of `"ok"` so these don't
   silently pollute future runs.
3. Re-extract and re-run the specific cases affected (`C_142`, `C_812`,
   `C_859`, `Cpp_732`, and any others the sanity check flags) once fixed.
4. Only then compute the metrics that matter for the go/no-go call.
