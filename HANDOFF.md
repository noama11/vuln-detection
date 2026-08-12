# Handoff — Unsupervised Vulnerability Detection Project

**Written**: 2026-08-12, end of a session that ran the full docstring-leakage
correction cycle and refreshed the wider-context ablation against it.
**Read this first**, then `PROGRESS.md` (full build history) and
`PILOT_INSIGHTS.md` (the original extraction-bug root-cause writeup) for
detail. `reports/ablation_report.md` and `reports/pilot_report.md` are the
current authoritative results documents — don't recompute conclusions from
memory, read them.

## 1. What this project is

Test whether an LLM given **only** a function's natural-language spec
(never its code), asked to reimplement it, and judged against the real code
by a second LLM, can surface security-relevant deviations without
supervised training — using real CVE fix-pairs (vulnerable vs. fixed
version of the same function) as ground truth. Two independent judge calls
per case (generated-vs-vulnerable, generated-vs-fixed), scored the same way,
so a vulnerability is "detected" when the Judge treats the two comparisons
differently in the right direction.

- **Generator** (Haiku, zero tools): sees only `{language, docstring}`
  (optionally `+file_context`, see §4). Writes an implementation.
- **Judge** (Sonnet, zero tools): sees `{specification, candidate,
  reference}` — never told which reference is "real" — twice per case.
  Outputs `score` (1-10), `category` (5-way), `security_relevant`,
  `rationale`.
- **Primary metric**: Paired Flag Accuracy — vulnerable-side scored
  `security_vulnerability_concern` AND fixed-side not. Pre-registered go/no-go
  bands: ≥80% GO, 60-80% expand pilot, <60% NO-GO rework first.
- Dataset: `D.zip`, 553 CVE-fix commits, 792 function-level cases, extracted
  into `cases/*.json` by `scripts/extract_cases.py`.

## 2. Current bottom line (as of this handoff)

**NO-GO, and now on solid footing.** Both the 27-case pilot (`reports/pilot_report.md`)
and the 14-case wider-context ablation (`reports/ablation_report.md`) show
**Paired Flag Accuracy ≈ 15.4%**, well under the 60% floor. This number is
now measured against **docstrings that have been audited and corrected for
leakage** (see §3) — it is not an artifact of leaked specs anymore. The
core, still-unsolved problem is what `PILOT_INSIGHTS.md` called **Finding
2**: the cheap Generator's output differs from *both* the vulnerable and
fixed reference in ways unrelated to the actual CVE, swamping the real
signal (the "baseline gap"). Giving the Generator more context (§4) does not
fix this and introduces its own new risk.

## 3. Docstring-leakage audit — done, applied, don't redo

**Problem found**: some `docstring` fields in `cases/*.json` inadvertently
state the vulnerability's fix (`describes_fixed_behavior`) or narrate the
buggy behavior as if normal (`describes_vulnerable_behavior`), letting the
Generator "solve" a case from the spec text alone.

**What was built**: `prompts/docstring_leakage_audit_system_prompt.txt`
(explicit non-malicious/defensive-research framing — this project reimplements
functions from *known, published* CVEs to build a detection method; make
sure any future API calls carry this framing, it's not optional boilerplate)
+ `scripts/audit_docstrings_llm_openai.py` (OpenAI Batches + Responses API;
`scripts/audit_docstrings_llm.py` is an equivalent, less-used Anthropic
version). Both write one result JSON per case to `reports/docstring_audit/`.

**What was run**: audited all 392 `extraction_status: "ok"` cases
(`--scope all`). Result: **153 confirmed_leak / 213 not_a_leak / 26
ambiguous**. `scripts/apply_docstring_fixes.py` spliced the neutral
rewrites into `cases/*.json`'s `docstring` field (format-preserving across
plain/triple-quoted/`/** */`/banner comment styles) — **152 of 153 applied**
(the 153rd, `C_652__0`, was a self-contradictory judge output — see §6 —
manually corrected to `not_a_leak`, not applied as a rewrite).

**Status: this is done.** `cases/*.json` docstrings are the corrected,
neutral versions going forward. Do not re-run the audit unless new cases are
added to the corpus or you have a specific reason to distrust a rewrite.

**Cost/secrets note**: this used the user's own OpenAI API key via a local
`.env` file (gitignored) — never accept a raw key in chat; only verify
presence/prefix/length without printing the value, and let the user manage
the env var/`.env` themselves. If a future run is needed, reuse this
pattern, don't improvise a new one.

## 4. Wider-context ablation — done, refreshed, has a real negative finding

**Question tested**: does giving the Generator the real vulnerable-side
source file (target function's body masked out, everything else real)
reduce the baseline gap and improve detection?

**Built**: `scripts/build_masked_context.py` (masks just the target
function's body; keeps file header, includes, macros, sibling functions);
wired into `.claude/agents/vuln-generator.md` as optional `file_context`;
two slash commands (`.claude/commands/run-case-ablation-{baseline,context}.md`)
+ `scripts/run_batch.ps1 -Run ablation_baseline|ablation_context`.
14 cases in `pilot/ablation_cases.json` (the "ok"-extraction subset of the
original 27-case pilot).

**This session's work**: 6 of the 14 ablation cases had leaked docstrings
(caught by §3's audit). Rather than statistically excluding them, both arms
were **regenerated from scratch** against the corrected docstrings — fresh
Generator + Judge calls for `C_385__0`, `C_481__0`, `C_591__0`, `C_761__0`,
`C_314__0`, `C_199__0`, in both `results/ablation_baseline/` and
`results/ablation_context/`. This gives a clean, non-excluded, apples-to-apples
comparison for the first time — see `reports/ablation_report.md` §
"Headline metrics (final)" for the full numbers and per-case table.

**Result: context does not help. If anything it's a wash-to-slightly-negative.**

| Metric | Baseline (docstring-only) | Context (docstring + masked file) |
|---|---|---|
| Paired Flag Accuracy | 15.4% (2/13) | 15.4% (2/13) — tied |
| Pairwise Ranking Accuracy | 38.5% (5/13) | 30.8% (4/13) — baseline wins |

**The interesting finding, worth reading in full in the report**: masking a
function's *body* does not mask the surrounding file's *coding idiom*. In
`C_761__0` (ImageMagick `GetPixelChannel`, CVE-2019-13299), the context arm
copied the CVE's exact vulnerable one-liner **verbatim** from three visible,
unmasked sibling accessor functions using the same buggy pattern — turning
what the baseline arm got *right* into a context-arm miss. The mirror case,
`C_623__0`, shows the same mechanism working in reverse (context correctly
imitates a *safe* sibling API, becoming the only clean context win in the
set). We deliberately did **not** exclude either of these cases from the
metrics — see the discussion in-conversation (not yet written into the repo)
for why: excluding a context-arm-only failure while keeping a context-arm-only
win would be one-sided cherry-picking, not a data-quality fix (unlike the
docstring leakage, which affected both arms symmetrically and was fair to
correct). **If a future agent is asked to "clean up" this ablation further,
push back the same way** unless the request is explicitly for a clearly-labeled
sensitivity check, not a replacement headline number.

**One correction made this session to the ablation report**: the per-case
table originally mis-stated `C_761__0`'s baseline-arm outcome as a miss; it
is actually a hit (`paired_flag_correct: true` in
`results/ablation_baseline/C_761__0.json`). This has been fixed in
`reports/ablation_report.md` — if you see this discrepancy referenced
anywhere else (e.g. in old chat transcripts), the report file is the
corrected version, trust it over anything else.

## 5. Files that matter (quick index)

| Area | File |
|---|---|
| Case extraction | `scripts/extract_cases.py`, `cases/*.json` |
| Generator/Judge agents | `.claude/agents/vuln-generator.md`, `.claude/agents/vuln-judge.md` |
| Orchestrators | `.claude/commands/run-case.md`, `run-case-ablation-{baseline,context}.md` |
| Batch driver | `scripts/run_batch.ps1` |
| Metrics | `scripts/compute_metrics.py` |
| Masked-context builder | `scripts/build_masked_context.py`, `pilot/masked_context/*.txt` |
| Docstring-leakage audit | `scripts/audit_docstrings_llm_openai.py`, `scripts/apply_docstring_fixes.py`, `prompts/docstring_leakage_audit_system_prompt.txt`, `reports/docstring_audit/*.json` |
| Results | `results/pilot/`, `results/ablation_baseline/`, `results/ablation_context/` (each with a `pilot_review.csv` for human review) |
| Reports (read these for conclusions) | `reports/pilot_report.md`, `reports/ablation_report.md`, `PILOT_INSIGHTS.md` (extraction bug root cause), `PROGRESS.md` (full build narrative) |

Two other audit artifacts exist but are lower-priority/superseded by the
LLM audit: `scripts/audit_docstring_alignment.py` (cheap heuristic prefilter,
`reports/docstring_alignment_audit.md`) and `pilot/leakage_audit_candidates.json`
(its 156-case output, which fed the first, partial pass of the LLM audit
before it was rerun at `--scope all`).

## 6. Known open issues / gotchas for whoever picks this up

1. **Extraction pipeline has a known ~49% clean rate.** Only 392/792 cases
   have `extraction_status: "ok"`; the rest are `suspect_identifier_mismatch`
   / `unsupported_multi_function_scope`, correctly excluded by
   `compute_metrics.py`. See `PILOT_INSIGHTS.md` Finding 1 for the root
   cause (brace-matching heuristic landing on the wrong function/nested
   block). Not re-investigated this session.
2. **The "baseline gap" (Finding 2) is still the dominant unsolved problem.**
   Neither the docstring fix nor the context ablation addressed it. It's
   the most likely next lever: e.g., escalating the Generator to a stronger
   model, or restructuring the Judge's rubric so a "both sides differ from
   my code for unrelated reasons" case doesn't automatically fail the pair.
3. **JSON schema field ordering can cause self-contradictory judge output.**
   Found once (`C_652__0` in the docstring audit — `verdict` before
   `rationale` in the schema led the model to commit to a verdict before
   reasoning). If you build more structured-output prompts, put
   rationale/evidence fields before the verdict field.
4. **Secrets**: never accept a raw API key in chat. `.env` is gitignored;
   the user manages it themselves. Only verify presence/prefix/length
   without printing the value.
5. **The `git status` at the start of this session showed a large,
   uncommitted diff** (152 `cases/*.json` docstring corrections + all the
   audit/ablation infrastructure/results). Nothing has been committed yet —
   check with the user before committing/pushing anything.

## 7. Recommended next steps, in order

1. **Decide what to do about Finding 2 (baseline gap) before scaling
   further** — this is the real blocker, not leakage or context anymore.
   Candidate directions: (a) escalate Generator model tier for a subset and
   compare, (b) rework the Judge rubric to separate "differs from both for
   unrelated reasons" from "differs specifically because of the CVE
   mechanism," (c) both.
2. **If pursuing file-context ablations further**, first fix the masking
   granularity issue noted in `reports/ablation_report.md` follow-ups
   (`Cpp_270__0` — preserve the target function's own signature line when
   masking, only mask the body) and treat the vulnerable-idiom-in-siblings
   risk (§4 here) as a designed-for constraint, not a bug — e.g. consider
   whether masking *all* structurally-similar sibling functions, not just
   the target, is worth testing as a follow-up ablation arm.
3. **Extraction pipeline** (`PILOT_INSIGHTS.md` §"Suggested next steps") is
   still open if anyone wants to push the "ok" fraction above ~49% before a
   full 792-case run.
4. **Do not** re-run the docstring leakage audit or re-exclude/re-include
   ablation cases without reading §3/§4 above first — both of those loops
   are closed for this corpus as it stands.
