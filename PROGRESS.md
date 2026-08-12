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

## 6. Wider-context ablation (done)

Note: by the time this ran, the extraction-bug fix from `PILOT_INSIGHTS.md`
Finding 1 had already been applied to `scripts/extract_cases.py` (added
`suspect_identifier_mismatch`/`unsupported_multi_function_scope` statuses).
Re-running it dropped the "ok" fraction of all 792 cases from the old ~94%
figure to **392/792 (49%)** and shrank the original 27-case pilot to just
**14 still-"ok" cases** (`pilot/ablation_cases.json`) - the other 13 are now
correctly excluded rather than silently polluting results.

Tested whether Finding 2 (cheap Generator's context-free reimplementation
differs from *both* references in similar, unrelated ways, swamping the real
signal) can be mitigated by giving the Generator the real vulnerable-side
file with the target function masked out, instead of only the docstring.
Built via `scripts/build_masked_context.py` (windowed to file header + ~40
lines around the mask to bound prompt size; never shows the target
function's real body on either side, so no fix-leakage risk). Wired into
`.claude/agents/vuln-generator.md` as an optional `file_context` field, and
into two new reproducible slash commands
(`.claude/commands/run-case-ablation-{baseline,context}.md`) plus
`scripts/run_batch.ps1 -Run ablation_baseline|ablation_context` for future
headless re-runs.

**Result** (`reports/ablation_report.md`, full detail): on the 14-case
ablation set, wider context raised **Paired Flag Accuracy from 15.4% to
38.5%** (2/13 → 5/13 non-degenerate cases, +23.1pp) with **zero
regressions** - every case correct at baseline stayed correct with context,
and 3 more (`C_591__0`, `C_623__0`, `C_199__0`) flipped from wrong to right,
in each case converging on essentially the real-world CVE fix without being
told about the CVE. ROC-AUC moved less (0.592 → 0.615). Both arms are still
below the pre-registered go/no-go bands (<60%) at this sample size, so this
is a promising direction-of-effect result, not a green light to scale yet.

Two follow-ups the ablation surfaced (see `reports/ablation_report.md` for
detail): (1) the masking window should preserve the target function's own
signature line - `Cpp_270__0` shows the Generator picking the wrong sibling
function when the signature is masked away entirely; (2) `C_761__0` revealed
a second docstring-leakage pattern (spec faithfully describing the
*vulnerable* behavior, not the fix) that the existing
`heuristic_leakage_flag` regex doesn't catch.

**Correction history (superseded by the final fresh re-run below):** an
initial pass over the 156-case heuristic-flagged subset found 3 of the 14
ablation cases leaked and gave a corrected Paired Flag Accuracy of 9.1% →
27.3%. Running the audit over the **full** ~392-case pool found 3 *more*
leaks inside the same 14-case ablation set that the smaller pass missed,
including `C_591__0` - previously counted as a genuinely clean win. **6 of 14
ablation cases were confirmed leaked, not 3.** Excluding all 6 (rather than
regenerating them) gave a leakage-*excluded* Paired Flag Accuracy of **0%
baseline vs. 12.5% (1/8) context** - a single case, not distinguishable from
chance.

**Final: both arms regenerated end-to-end against corrected docstrings
(done).** Rather than continuing to exclude the 6 leaked cases, they were
regenerated from scratch - fresh Generator and Judge calls, both arms -
against the corrected, neutral docstrings applied in §7. This gives a clean,
non-excluded, apples-to-apples 14-case comparison for the first time:
**Paired Flag Accuracy ties at 15.4% (2/13) for both arms**, and Pairwise
Ranking Accuracy actually **favors the docstring-only baseline** (38.5% vs.
30.8%). One case (`C_761__0`) surfaced a new negative finding: with the
masked source file in context, the Generator directly reproduced the CVE's
exact vulnerable one-liner instead of reconstructing it independently -
i.e., file context can leak the vulnerable pattern itself, not just via
docstring wording. `C_623__0` remains the only clean context-arm win (its
docstring was never leaked). **Current verdict: context does not clearly
help on this sample - a tie on the primary metric, a loss on the secondary
one.** Both arms remain below the go/no-go bands (<60%). See
`reports/ablation_report.md` § Headline metrics (final) / § Verdict (final)
for the complete writeup, including the full per-case table and follow-ups.

## 7. LLM-based docstring-leakage audit (done for the 156-case candidate set)

The cheap heuristic screen (`scripts/audit_docstring_alignment.py`, §
`reports/docstring_alignment_audit.md`) sized the leakage problem across all
392 "ok" cases (23.2% vulnerable-echo-leaning, 14.5% fix-leak-leaning) and
produced 156 candidates (`pilot/leakage_audit_candidates.json`). Built an LLM
verification pass on top: `prompts/docstring_leakage_audit_system_prompt.txt`
(explicit non-malicious/defensive-research framing + a precise
confirmed/not/ambiguous decision procedure + a neutral-rewrite request) and
two equivalent batch-runner scripts,
`scripts/audit_docstrings_llm.py` (Anthropic Batches API) and
`scripts/audit_docstrings_llm_openai.py` (OpenAI Batches + Responses API,
used for the actual run - both write to the same `reports/docstring_audit/`
so they're interchangeable). Both support `--resume-batch-id` to reconnect
to an already-submitted batch if the local process is interrupted (the batch
itself keeps running server-side regardless).

**Result on the 156-case candidate set** (`gpt-5.6-terra`):
**81 confirmed_leak (52%), 58 not_a_leak (37%), 17 ambiguous (11%)**. Each
confirmed-leak result includes a proposed neutral rewrite of just the `Logic`
section, sitting in `reports/docstring_audit/<case_id>.json` - **not yet
applied to `cases/*.json`**, pending a decision on how/whether to splice
these back into the corpus (the docstring format varies enough across cases -
plain, triple-quoted, C-block-comment - that a mechanical splice needs
per-format handling, and applying at all raises the question of what happens
to already-published results that reference the pre-fix docstring text, as
above).

**Applied.** `scripts/apply_docstring_fixes.py` spliced all 81 rewritten
`Logic` sections into `cases/*.json`'s `docstring` field (format-preserving
across plain/triple-quoted/`/** */`/banner styles - verified via dry-run spot
checks first, then a real run: 81/81 succeeded, 0 needed manual attention).
Each diff touches only the `docstring` field, nothing else. This means
`cases/*.json` and the docstrings referenced in already-published results
(`results/pilot/`, `results/ablation_*/`) now diverge for any case that was
both audited and previously run - expected and intentional (ground truth was
corrected; historical results are understood as "measured against the
pre-fix docstring," per the correction notes above and in
`reports/ablation_report.md`). Any *new* run from this point on uses the
fixed docstrings automatically.

**What's left**: whether to run the audit over the full ~392-case pool
(`--scope all`) rather than just the heuristic-flagged 156 - the 156 were a
high-recall prefilter, so real leaks likely exist outside that set too, just
at lower density.
