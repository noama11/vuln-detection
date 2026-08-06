# Unsupervised Vulnerability Detection — Progress So Far

## Goal

Test whether an LLM that is given **only** a function's documentation (never
its code), asked to reimplement it, and then judged against the real code by
a second LLM, can surface security-relevant deviations without any
supervised training — using real CVE fix pairs as ground truth.

## 1. Dataset inspection (read-only, no files modified)

`D.zip` (~15 MB) was opened and inspected before anything was built.

- **553 real CVE-fix samples**: 532 C, 21 C++, from 92 repos (51%
  `torvalds/linux`; also Chromium, ImageMagick, FFmpeg, libarchive, etc).
- Structure: `D/{C,C++}/{id}/{config.json, vulnerable.<ext>, fixed.<ext>}`.
  `vulnerable.<ext>`/`fixed.<ext>` are **full source files**, not isolated
  functions.
- `config.json` per sample: `cve_id`, `cve_summary`, `commit_message`,
  `changed_lines` (diff hunk line ranges, before/after), and `scope` — one
  entry per function touched by the fix, each with `{start, end, docstring}`.
  The `docstring` is an already-generated structured summary
  (Summary/Parameters/Returns/Logic) of that function.
- **No README** in the zip — this schema was fully reverse-engineered from
  the data itself.
- **792 function-level cases** across the 553 commits (most commits touch 1
  function; some touch up to 9).
- **No CWE/severity field** — only free-text `cve_id`/`cve_summary`, so
  ground truth is binary and pair-structured (every case has a `vulnerable`
  and a `fixed` version of the same function), not multi-class.

### Key risk found during inspection: docstring leakage

Manual spot-checks found that some docstrings describe logic that only
exists in the **fixed** code, not the vulnerable code they're nominally
summarizing. Example: CVE-2013-0211 (libarchive) — the docstring says "It
limits the size of the data to be written to the maximum allowable value to
prevent overflow," but `vulnerable.c` at those exact lines has no such logic;
only `fixed.c` does. This means the "spec" sometimes already encodes the fix,
which would make detection trivially easy for the wrong reason on those
cases. It's not universal (other spot-checks were faithful, blind
summaries), so the plan measures this rather than assuming it away.

## 2. Plan (reviewed by a second agent before approval)

A Plan-agent review caught several issues that were folded into the final
design:
- **Judge-side leakage channel**: telling the Judge which snippet is
  "vulnerable" vs "fixed" would let it pattern-match the answer. Fixed by
  always labeling the reference snippet neutrally ("reference
  implementation") and running two fully independent Judge calls.
- **Naive pairing bug**: for commits touching multiple functions, matching
  `scope` entries to `changed_lines` entries by list position is wrong a
  meaningful fraction of the time — fixed by matching on line-range overlap.
- **Missing "generator produced garbage" category** — added
  `degenerate_generation`, excluded from all accuracy metrics so pipeline
  failures don't silently corrupt the numbers.
- **Weak primary metric** — switched from a soft ranking metric to a
  stricter, more meaningful **Paired Flag Accuracy** (see Metrics below).

Full plan: `C:\Users\nosm1\.claude\plans\please-buil-a-deep-idempotent-cookie.md`

## 3. What was built

| Component | File | Purpose |
|---|---|---|
| Case extraction | `scripts/extract_cases.py` | Unzips `D.zip`, matches `scope`↔`changed_lines` by line-overlap, extracts the vulnerable-side snippet by line range, locates the same function in `fixed.<ext>` via brace-pair anchoring (robust to C++ namespace/class nesting), writes one JSON per function-case to `cases/`. |
| Pilot selection | `scripts/select_pilot.py` | Stratified sample of 27 cases: floor of 5 C++ cases, 7 deliberately leakage-flagged cases, rest spread across repos/function sizes. Writes `pilot/pilot_cases.json`. |
| Generator subagent | `.claude/agents/vuln-generator.md` | Sees **only** `{language, docstring}`. Zero tools (`tools: []`). Model: Haiku. Outputs one function implementation, no security framing. |
| Judge subagent | `.claude/agents/vuln-judge.md` | Sees `{specification, candidate_implementation, reference_implementation}` — never told which side is "real." Zero tools. Model: Sonnet. Outputs structured JSON: `score` (1-10), `category` (5-way: `equivalent_implementation_difference` / `functional_mismatch` / `quality_bug` / `security_vulnerability_concern` / `degenerate_generation`), `security_relevant`, `confidence`, `rationale`. Includes a decision rubric + worked examples. |
| Orchestrator | `.claude/commands/run-case.md` | Slash command `/run-case <case-file>`: reads the case, calls generator once, calls judge twice (vs. vulnerable, vs. fixed — fresh, independent calls), computes `pairwise_ranking_correct` / `paired_flag_correct`, writes the merged result to `results/<pilot\|full_run>/<case_id>.json` + snippet dumps for manual review. |
| Batch driver | `scripts/run_batch.ps1` | Loops `claude -p "/run-case ..."` over a case list. Idempotent (skips cases with an existing result file) and retries once on failure. |
| Metrics | `scripts/compute_metrics.py` | Flattens results into `results/<run>/pilot_review.csv` (blank human-label columns) and computes: **Paired Flag Accuracy** (primary), Pairwise Ranking Accuracy (secondary), ROC-AUC + Youden's J (diagnostic), generation-failure rate, Cohen's kappa vs. human labels, and a leakage-excluded version of every headline number. Unit-tested on synthetic data (perfect separation → AUC 1.0; perfect/zero kappa agreement both checked). |
| Permissions | `.claude/settings.local.json` | Scoped so headless `claude -p` runs without interactive prompts (`Read`, `Edit(results/**)`, `Task(vuln-generator)`, `Task(vuln-judge)`). |

### Bug found and fixed during smoke-testing

Both agent files originally set `tools: TodoWrite` as a minimal "harmless"
placeholder (there's no official `tools: []`/`tools: none` syntax per the
general docs). In practice, `TodoWrite` isn't a valid tool name in this
environment, so both subagents silently failed to launch. The actual runtime
error revealed that `tools: []` (a genuinely empty list) **does** work here
— fixed in both agent files.

## 4. Pilot run — in progress

27 cases selected; running via `scripts/run_batch.ps1 -Run pilot` in the
background. Results land in `results/pilot/<case_id>.json` as they complete.

### Early results (2/27 so far — not enough to draw conclusions from yet)

1. **`C_114__0`** (libarchive, CVE-2013-0211, leakage-flagged): Generator
   added a size clamp (the docstring told it to), but used `SSIZE_MAX`
   instead of the real fix's `INT_MAX`. Judge correctly flagged the
   vulnerable side (no clamp at all) — but also flagged the fixed side,
   since the generated clamp's threshold is technically too permissive.
   Defensible judge reasoning, not a bug.
2. **`Cpp_270__0`** (InspIRCd, CVE-2016-7142): the real function requires a
   SASL capability-negotiation check present in **both** the vulnerable and
   fixed versions. The generated code ignores that parameter entirely
   (the docstring names it without explaining its security role), so it's
   less careful than both reference versions for reasons unrelated to the
   actual CVE — and the ranking even came out backwards (vulnerable scored
   *higher* than fixed).

**Pattern to watch**: when a docstring names a parameter without explaining
its security role, the cheap Generator model appears to drop functionality
it doesn't understand, which can flood the signal with noise unrelated to
the real vulnerability. Worth watching as more cases land — may push toward
escalating the Generator to Sonnet for object-heavy C++ cases.

## 5. What's left

- [ ] Finish the remaining pilot cases (batch running now).
- [ ] Human review of all 27 cases via `results/pilot/pilot_review.csv`
      (fill in `human_category`, `human_is_security_relevant_function`,
      `human_docstring_leakage_suspected`, `human_notes`).
- [ ] Run `scripts/compute_metrics.py pilot` for the full metrics + go/no-go
      report (`reports/pilot_report.md`).
- [ ] Apply the pre-registered decision bands: Paired Flag Accuracy ≥80% →
      go to full 792-case run; 60-80% → expand pilot to ~60 cases; <60% →
      rework rubric/prompts before scaling.
