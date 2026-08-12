# Wider-context ablation — docstring-only vs. docstring + masked-file context

**Question**: does giving the Generator the real vulnerable-side file (target
function masked out, everything else real - includes, macros, types, sibling
functions) reduce the "baseline gap" noise identified in `PILOT_INSIGHTS.md`
Finding 2, and improve detection of the actual CVE fix?

> **Update 3 (final - fully fresh comparison, supersedes Update 1 and Update
> 2's leakage-exclusion framing):** all 14 ablation cases' docstrings are now
> corrected (152 corpus-wide rewrites from the LLM leakage audit, applied
> before this run - see `PROGRESS.md` §6-7). Rather than continuing to exclude
> leaked cases from the old (pre-fix) results, **both arms were regenerated
> from scratch** for the 6 cases the audit had flagged in this set
> (`C_385__0`, `C_481__0`, `C_591__0`, `C_761__0`, `C_314__0`, `C_199__0`) -
> fresh Generator + Judge calls against the corrected, neutral docstrings, for
> both the baseline and context arms. The other 8 cases were never flagged as
> leaked and are unchanged. This is a clean, non-excluded, apples-to-apples
> comparison: **Paired Flag Accuracy ties at 15.4% (2/13) for both arms**, and
> **Pairwise Ranking Accuracy now favors the baseline** (38.5% vs 30.77%). See
> **§ Headline metrics (final)** and **§ Verdict (final)** below; the
> leakage-exclusion history (Updates 1-2) is kept further down for the record
> but is no longer the operative conclusion.

## Setup

- **Cases**: the 14 of the original 27 pilot cases that still have
  `extraction_status: "ok"` after the extraction-bug fix landed (see
  `pilot/ablation_cases.json`; the other 13 are now `suspect_identifier_mismatch`
  / `unsupported_multi_function_scope` and excluded, consistent with how the
  full pilot metrics already treat them).
- **Baseline arm** (`results/ablation_baseline/`): unchanged pipeline -
  Generator sees only `{language, docstring}`. 8/14 reused verbatim from the
  earlier partial pilot run (same Haiku/Sonnet config, verified); 6/14 run
  fresh for this ablation.
- **Context arm** (`results/ablation_context/`): Generator additionally sees
  `file_context` - the real vulnerable-side source file with the target
  function's body masked out (built by `scripts/build_masked_context.py`,
  windowed to file header + ~40 lines around the mask to bound prompt size;
  see `pilot/masked_context/`). `.claude/agents/vuln-generator.md` was
  extended to use this when present; the Judge and its rubric are byte-for-byte
  unchanged between arms - only the Generator's input differs.
- Both arms use the same 14 cases, same Judge, run independently (each
  Generator call and each Judge call is a fresh, isolated subagent
  invocation, per the project's information-isolation design).

## Headline metrics (final, fresh, no exclusions)

| Metric | Baseline (docstring-only) | Context (docstring + masked file) | Δ |
|---|---|---|---|
| Paired Flag Accuracy (primary) | **15.4%** (2/13) | **15.4%** (2/13) | **0** |
| Pairwise Ranking Accuracy | **38.5%** (5/13) | 30.8% (4/13) | **-7.7 pp** |
| ROC-AUC | 0.547 | 0.420 | -0.127 |
| Generation-failure rate | 7.1% (1/14, the known-bad `C_651__0` extraction) | 7.1% (same case) | 0 |

(n_scored=13 in both arms: 14 cases minus `C_651__0`, excluded in both arms
as a mismatched-extraction artifact unrelated to the Generator/Judge, same as
the pre-existing pilot convention for `degenerate_generation`.)

Full auto-generated reports: `reports/ablation_baseline_report.md`,
`reports/ablation_context_report.md`. Per-case CSVs:
`results/ablation_baseline/pilot_review.csv`,
`results/ablation_context/pilot_review.csv`.

## Per-case comparison (final, fresh numbers)

| case_id | baseline paired_flag_correct | context paired_flag_correct | what changed |
|---|---|---|---|
| Cpp_270__0 | ✗ | ✗ | unaffected by the docstring fix; context arm's Generator implemented the wrong sibling class at the mask point (masking-granularity issue, see follow-up 1) |
| Cpp_711__2 | ✗ | ✗ | unaffected; both arms got the RC4 key-XOR loop wrong |
| Cpp_478__1 | ✗ | ✗ | unaffected; context arm introduced its own distinct OOB write |
| Cpp_377__0 | ✗ | ✗ | unaffected; context matched the fix's unsigned-type choice but introduced a new off-by-one |
| C_385__0 | ✗ | ✗ | corrected docstring, both arms regenerated - both still miss the fix (`rcv_mss` init), and omit unrelated cleanup logic on both sides regardless of arm |
| C_143__0 | ✗ | ✗ | unaffected; struct-only case, both arms picked wrong buffer sizes |
| C_481__0 | ✗ | ✗ | corrected docstring, both arms regenerated - both arms independently add a malloc-null-check that also flags the *reference*'s own missing check, so both sides score `security_vulnerability_concern` for different reasons (a "baseline gap" case, not a clean signal, in both arms) |
| **C_761__0** | **✓** | ✗ | corrected docstring, both arms regenerated - **baseline flags this correctly** (docstring-only Generator wrote a different, non-matching implementation that the Judge correctly distinguished from vulnerable); **context arm regression**: with the masked vulnerable-side file in context, the Generator instead reproduced the CVE's exact vulnerable one-liner verbatim (copied from three visible sibling accessor functions using the same idiom), scoring 10/equivalent vs. vulnerable - i.e. context handed it the bug to copy, turning a correct baseline detection into a context-arm miss |
| C_467__1 | ✗ | ✗ | unaffected; both arms missed the real bug, and context arm's version now also gets flagged as security-concern on both sides |
| C_591__0 | ✗ | ✗ | corrected docstring, both arms regenerated - both arms independently reproduce the naive fixed-`/tmp`-path pattern instead of the fix's randomized filenames; context did not help |
| **C_623__0** | ✗ | **✓** | unaffected by docstring correction; the one case where context arm avoids the real CVE mechanism using the real `darray_*` API shown in context - a genuine, reproducible context win |
| C_651__0 | excluded (known-bad extraction) | excluded (same) | — |
| C_314__0 | ✓ | ✓ | corrected docstring, both arms regenerated - both arms independently arrive at the same safe two-pass `OBJ_obj2txt`-sizing pattern; correct in both, holds up post-correction |
| C_199__0 | ✗ | ✗ | corrected docstring, both arms regenerated - context arm's struct now correctly embeds `SCSIRequest req` by value (closer to real usage) but the Judge still scored both sides too close together to register as a flag win; baseline uses a wrong pointer-based layout |

**Net effect of the fresh re-run**: five of the six previously-leaked cases
mostly settle into "baseline gap" territory in both arms
(`security_vulnerability_concern` on both vulnerable- and fixed-side, for
reasons unrelated to the actual CVE), rather than becoming clean wins for
either arm. The sixth, `C_761__0`, is a concrete **negative** finding for
context, on this fresh, non-leaked run: the docstring-only baseline arm
flags it correctly, but the context arm - given the masked vulnerable-side
file - directly reproduced the CVE's exact vulnerable one-liner (copied
verbatim from three visible, unmasked sibling functions using the same
idiom), converting a correct baseline detection into a context-arm miss.
`C_623__0` remains the only clean, context-only win across all 14 cases.
Net: one clean context win, one clean context loss, both traceable to the
same mechanism (the model imitating whatever style is visible around the
masked function) - which is exactly why the aggregate numbers land close to
a tie rather than a clear win for either arm.

## Old per-case comparison (leakage-affected results, superseded by the table above)

| case_id | baseline paired_flag_correct | context paired_flag_correct | what changed |
|---|---|---|---|
| Cpp_270__0 | ✗ | ✗ | context arm's Generator, seeing no visible function signature at the mask point, implemented the *wrong* sibling class (`CommandSASL` instead of `CommandAuthenticate`) - a masking-granularity issue, not a content-quality regression |
| Cpp_711__2 | ✗ | ✗ | both arms got the RC4 key-XOR loop wrong |
| Cpp_478__1 | ✗ | ✗ | context arm introduced its own distinct OOB write, unrelated to the real CVE |
| Cpp_377__0 | ✗ | ✗ | context correctly matched the real fix's unsigned-type choice, but introduced a new, different off-by-one |
| C_385__0 (**leakage-confirmed**) | ✗ | ✗ | docstring names the fix outright ("avoid division by zero"); both arms still got the actual value wrong (`0` instead of `TCP_MIN_MSS`) |
| C_143__0 | ✗ | ✗ | struct-only case; both arms picked wrong buffer sizes |
| C_481__0 (**leakage-confirmed**) | ✓ | ✓ | correct in both - but confirmed leaked (`describes_fixed_behavior`), so this "win" is spec-driven, not evidence of either arm's reconstruction ability |
| C_761__0 (**leakage-confirmed**) | ✗ | ✗ | docstring describes the *vulnerable* behavior, not the fix (`describes_vulnerable_behavior`) - both arms still wrong anyway |
| C_467__1 | ✗ | ✗ | both arms missed the real bug (stale buffer-position reset) |
| C_591__0 (**leakage-confirmed**) | ✗ | **✓** | docstring leak confirmed (`describes_fixed_behavior`) - the earlier "clean win" framing was wrong; this is spec-driven, not a context-arm success |
| **C_623__0** | ✗ | **✓** | the one case that survives as a genuinely clean win - context arm avoided the real CVE mechanism (invalid free via `&append`) using the real `darray_*` API shown in context |
| C_651__0 | excluded (known-bad extraction) | excluded (same) | — |
| C_314__0 (**leakage-confirmed**) | ✓ | ✓ | correct in both - but the docstring names the exact `BIO_printf`/`OBJ_obj2txt` pattern the *fix* uses, so this was largely answered by the spec |
| C_199__0 (**leakage-confirmed**) | ✗ | ✓ | docstring names the `buflen` field, which only exists post-fix - so leaked, though context still had to correct an unrelated struct-layout mistake for the leaked detail to register (see prior note, now superseded as a "clean win" claim) |

**6 of the 14 ablation cases are confirmed leaked** (`C_385__0`, `C_481__0`,
`C_591__0`, `C_761__0`, `C_314__0`, `C_199__0`) - see § Leakage-corrected
metrics for what's left once they're excluded.

## Historical: leakage-exclusion pass (superseded by the fresh re-run above)

This section is kept for the record; it reflects the *old* results (before
the 6 leaked cases were regenerated against corrected docstrings) with
leakage-flagged cases excluded rather than fixed. The fresh, non-excluded
comparison in **§ Headline metrics (final)** above is the current answer.

Excluding all 6 leakage-flagged ablation cases via `scripts/compute_metrics.py`'s
existing `human_docstring_leakage_suspected` mechanism:

| Metric | Baseline, leakage-excluded | Context, leakage-excluded | Δ |
|---|---|---|---|
| Paired Flag Accuracy | **0%** (0/8) | **12.5%** (1/8) | **+12.5 pp** |
| Pairwise Ranking Accuracy | 25% (2/8) | 12.5% (1/8) | **-12.5 pp** |
| ROC-AUC | 0.516 | 0.406 | -0.109 |

`compute_metrics.py` itself flags this divergence as no-go-strength per the
plan's own pre-registered rule ("leakage-excluded accuracy diverging
substantially from the overall figure is a no-go signal regardless of the
overall number"). The Paired Flag Accuracy edge is a single case
(`C_623__0`) out of 8 - not distinguishable from chance at this n - and the
secondary metric (Pairwise Ranking) actually favors baseline on the clean
subset. This ablation does **not** currently support a "context helps"
conclusion.

## Verdict (final)

**Context does not help on this 14-case sample - if anything, it's a wash to
slightly negative.** With all six previously-leaked cases regenerated from
scratch against corrected, neutral docstrings (not excluded - actually
re-run), Paired Flag Accuracy is **tied at 15.4% (2/13) for both arms**, and
Pairwise Ranking Accuracy actually **favors the docstring-only baseline**
(38.5% vs. 30.8%). The one genuinely clean context win, `C_623__0`, is
unaffected by any of this (its docstring was never leaked) and remains the
single interesting positive data point for the context arm - unchanged from
before. Working against it is a genuine negative finding: `C_761__0` shows
that giving the Generator the masked source file can backfire by letting it
directly copy the vulnerable pattern from the visible context rather than
reconstructing it independently, converting a would-be correct detection
into a miss.

**Both arms remain below the pre-registered go/no-go bands** (15.4% is
`<60%` → **NO-GO**) on Paired Flag Accuracy. This is no longer a
leakage-confound question - both arms now reflect the same corrected,
non-leaking specs, and the result is a genuine, if underpowered (n=13), tie.
Wider file context, at least in this masked-single-file form, is not
currently a substitute for a better spec or a better rubric; the earlier
docstring-only pilot's core problem (`PILOT_INSIGHTS.md` Finding 2's "baseline
gap" - the Generator's output differs from *both* reference implementations
for reasons unrelated to the actual CVE) shows up in both arms about equally
often. Scaling up case count would sharpen the estimate but is unlikely to
flip this conclusion without also addressing the rubric/prompt issues the
pilot already flagged.

## Follow-ups surfaced by this ablation

1. **Preserve the function signature line when masking.** `Cpp_270__0`
   shows the masking window sometimes cuts off exactly at the signature,
   leaving the Generator no cue about which declaration follows the mask
   marker - it filled in a plausible but wrong sibling. Fix:
   `build_masked_context.py` should keep the target's own signature line (up
   to the opening `{`) visible and mask only the body.
2. **A second docstring-leakage pattern, now confirmed systematically**:
   `C_761__0`'s docstring faithfully describes the *vulnerable* function's
   logic, not the fixed one - the inverse of the leakage risk the original
   `heuristic_leakage_flag` regex was built to catch. The LLM audit
   (`scripts/audit_docstrings_llm_openai.py`) checks both directions by
   design and confirmed this one, along with 152 others across the corpus -
   all now fixed in `cases/*.json`.
3. ~~**Re-run this ablation against the corrected corpus**~~ - **done**: the 6
   leaked cases were regenerated end-to-end (fresh Generator + Judge, both
   arms) against corrected docstrings; results are in **§ Headline metrics
   (final)** above. Verdict: tied paired-flag accuracy, baseline-favoring
   ranking accuracy - context does not clearly help on this sample.
4. **New finding: masked file context can leak the vulnerable pattern
   directly, not just via the docstring.** `C_761__0`'s context arm
   reproduced the CVE's exact one-line vulnerable condition verbatim once
   given the masked source file, where the docstring-only baseline arm did
   not. This is a different leakage vector than docstring wording - the
   *code* surrounding the masked function can itself telegraph the bug (e.g.
   via sibling functions, similar patterns elsewhere in the file, or the
   masking boundary sitting too close to the vulnerable logic). Worth
   checking whether this generalizes across more context-arm cases before
   trusting file-context ablations as a leakage-free alternative to
   docstring-only prompts.
5. **Sample size remains the binding constraint.** At n=13 scored cases per
   arm, a 2-case swing (`C_623__0` vs. `C_761__0`) is the entire margin
   between "context ties baseline" and "context loses to baseline." Neither
   this ablation nor the pilot it's drawn from can distinguish a real small
   effect from noise; expanding case count is the honest next step if this
   question is still worth answering, but only after the rubric/prompt
   issues underlying the "baseline gap" (`PILOT_INSIGHTS.md` Finding 2) are
   addressed, since that gap currently swamps both arms about equally.
