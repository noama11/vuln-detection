# Experiment: Local Qwen3-32B arm of the spec-reconstruction detector

**Date run**: 2026-08-14
**Branch**: `docstring-leakage-audit-and-context-ablation`
**Artifacts**: `results/qwen_full/` (391 case records + per-case snippets),
`reports/qwen_full_report.md` (auto-generated), `results/qwen_full/pilot_review.csv`
**Comparator**: `results/ablation_baseline/` = `results/pilot/` (verified byte-identical
verdicts on all 14 shared cases; they are the same Haiku+Sonnet docstring-only arm)

---

## 1. Objective

Two questions in one run:

1. **Does the detector work at corpus scale?** The existing Haiku+Sonnet result
   (Paired Flag Accuracy 15.4%) rested on 13 scored cases. That is too few to
   distinguish "the method fails" from "the sample was unlucky."
2. **Is model capability the bottleneck?** `HANDOFF.md` §7 named escalating the
   Generator's model tier as the top candidate fix for the "baseline gap"
   (Finding 2). Running a 32B model in both roles tests that directly.

Running inference locally makes both affordable: the full 392-case corpus costs
nothing and finishes in 16 minutes, versus a metered API run.

## 2. Method (unchanged from the Claude arm)

For each case we have a CVE fix commit and therefore two versions of the same
function: **vulnerable** (pre-patch) and **fixed** (post-patch), plus a
natural-language `docstring` describing what the function should do.

1. **Generator** receives `{language, docstring}` and *only* that — never any
   source code, CVE identifier, repository name, or commit message. It writes an
   implementation from scratch (the **candidate**).
2. **Judge** is called **twice**, independently:
   - candidate vs **vulnerable** snippet
   - candidate vs **fixed** snippet

   It is never told which reference is which, or that one of them contains a
   vulnerability. Each call returns `score` (1–10), `category` (5-way),
   `security_relevant`, `confidence`, `rationale`.
3. A case counts as **detected** when the judge assigns
   `security_vulnerability_concern` to the vulnerable side **and not** to the
   fixed side. The rate of this is **Paired Flag Accuracy (PFA)**, the
   pre-registered primary metric (go/no-go bands: ≥80% GO, 60–80% expand, <60%
   NO-GO).

The underlying hypothesis: a clean-room implementation written from a correct
spec should resemble *correct* code, so the vulnerable comparison should surface
the defect while the fixed comparison stays clean.

## 3. What differs in this arm

Only the **execution substrate**. The prompts are not reimplemented — the driver
reads the Generator and Judge system prompts directly out of
`.claude/agents/vuln-{generator,judge}.md` (YAML frontmatter stripped) and
records a digest of them (`prompt_sha = 1de29ae28c7d`) in every result record, so
prompt drift between arms is detectable rather than assumed absent.

| | Claude arm | Qwen arm (this experiment) |
|---|---|---|
| Generator | Claude Haiku | Qwen3-32B-AWQ |
| Judge | Claude Sonnet | Qwen3-32B-AWQ |
| Orchestration | `/run-case` slash command → Task subagents | `scripts/run_cases_local.py` |
| JSON validity | best-effort parse of model output | grammar-constrained decoding (schema-enforced) |
| Cases | 14 (the `"ok"` subset of a 27-case pilot) | 391 |
| Wall clock | — | 16 min, 1173 model calls |

**Serving**: vLLM 0.11.0, Qwen3-32B-AWQ (4-bit, W4A16), single RTX 4090 (24 GB),
`max_model_len` 16384, fp8 KV cache (26,512 tokens), `max_num_seqs` 8, prefix
caching on. Concurrency 8. Thinking mode **off**. `temperature`: 0.2 generator /
0.0 judge, `seed` 1234.

**One deliberate prompt change**: the Judge's user message carries an appended
line pinning JSON key order to `rationale` before the verdict fields. Grammar-
constrained decoding emits keys in schema-declaration order, and `HANDOFF.md` §6
documents a case (`C_652__0`) where verdict-first ordering produced
self-contradictory output. Recorded per-record as
`runtime.judge_key_order: "rationale_first"`. The rubric text itself is unchanged.

**Coverage**: 392 cases carry `extraction_status: "ok"` (of 792 total). 391 ran;
1 (`C_1313__0`) was skipped for exceeding the context window (~20.4k tokens
estimated). **0 failures.**

---

## 4. Results

### 4.1 Headline — full corpus (n = 391, 357 scored)

| Metric | Value | 95% CI | Pre-registered floor |
|---|---|---|---|
| **Paired Flag Accuracy** | **16.0%** (57/357) | [12.5%, 20.1%] | 60% → **NO-GO** |
| Pairwise Ranking Accuracy | 26.3% (94/357) | [22.0%, 31.1%] | — |
| ROC-AUC | **0.475** | — | 0.50 = chance |
| Youden's J | 0.0 (threshold 1) | — | — |
| Generation-failure rate | 8.7% (34/391) | — | — |

The confidence interval excludes the 60% floor by a wide margin. **The 15.4%
pilot figure was not a small-sample artifact** — at 27× the sample size the
estimate is 16.0%.

### 4.2 The full outcome distribution

PFA alone hides the shape of the failure. All four judge-verdict combinations,
n = 391:

| Outcome | Cases | Share |
|---|---|---|
| Flags vulnerable only — **method working** | 59 | 15.1% |
| Flags fixed only — **exactly backwards** | 68 | 17.4% |
| Flags both — cannot discriminate | 90 | 23.0% |
| Flags neither — misses the CVE | 174 | 44.5% |

**The detector is wrong-way-round more often than it is right** (68 vs 59).

### 4.3 Three independent demonstrations of no signal

**(a) The flag rate barely responds to the vulnerability.** Over the 357 scored
cases the Judge calls the vulnerable code a security concern 41.2% of the time
and the *patched* code 44.0% of the time. Removing the vulnerability does not
reduce the flag rate.

**(b) The scores point the wrong way.** Mean judge score against vulnerable
code 3.75, against fixed code 3.57 — a difference of **−0.18** on a 1–10 scale.
A working detector requires this to be clearly positive. ROC-AUC 0.475
confirms it at 0.025 below chance.

**(c) It underperforms its own chance baseline** — the strongest evidence,
because it is threshold-free and rubric-free. Given the marginal flag rates
above, two *statistically independent* judgments would yield
0.412 × (1 − 0.440) = **23.1%** PFA by luck alone. Observed: **16.0%**.

Falling *below* the product of the marginals means the two judge calls are
**positively correlated**. They share exactly one input — the candidate
implementation — and differ only in the reference. So the Judge is responding
principally to properties of the generated code, not to the reference it was
shown. **The reference barely enters the decision.** That is the "baseline gap"
(Finding 2) measured directly rather than inferred.

### 4.4 Comparison with the Haiku+Sonnet arm

The two arms overlap on 14 cases (`pilot/ablation_cases.json`). Comparing on
that matched subset is the only valid arm-vs-arm comparison; the full-corpus
column is shown for scale but is a different case set.

| Metric | Haiku + Sonnet (n=14) | Qwen3-32B (matched n=14) | Qwen3-32B (full n=391) |
|---|---|---|---|
| Paired Flag Accuracy | 15.4% (2/13) | 7.7% (1/13) | 16.0% (57/357) |
| Pairwise Ranking Accuracy | 38.5% (5/13) | 53.8% (7/13) | 26.3% (94/357) |
| ROC-AUC | 0.547 | 0.488 | 0.475 |
| Generation-failure rate | 7.1% (1/14) | 7.1% (1/14) | 8.7% (34/391) |
| Mean score, vulnerable | 4.08 | 5.08 | 3.75 |
| Mean score, fixed | 4.08 | 4.62 | 3.57 |

**On the matched subset the two arms are statistically indistinguishable**
(2/13 vs 1/13, Fisher exact **p = 1.000**; the Wilson CIs, [4.3%, 42.2%] and
[1.4%, 33.3%], overlap almost entirely). n = 13 cannot separate these arms, and
no claim that either model is better is supportable from it. The matched-subset
Pairwise Ranking figures illustrate the danger directly: Qwen looks *better*
there (53.8% vs 38.5%) yet scores 26.3% on the full corpus — the 14-case sample
is not representative of the corpus.

**The defensible cross-arm claim is the null one**: substituting a 32B model for
Haiku+Sonnet moved the primary metric from 15.4% (n=13) to 16.0% (n=357). Two
substantially different model stacks land in the same place, which makes "the
generator/judge was not strong enough" a weak explanation for the baseline gap
and redirects suspicion to the task formulation and rubric.

### 4.5 The arms disagree at the case level

Despite near-identical aggregate scores, the two arms do not agree about *which*
cases are which — on the matched 14:

- Verdict-level agreement: **9/28 = 32.1%**
- **Cohen's κ = 0.091** (5-way category) — barely above chance agreement
- Cases detected by Haiku+Sonnet: `C_314__0`, `C_651__0`, `C_761__0`
- Cases detected by Qwen3-32B: `C_591__0`
- **Overlap: none**

If the method carried signal, both arms should tend to succeed on the same
(easier) cases. Zero overlap across four total detections is what one expects if
individual detections are noise. The matching aggregate PFA of the two arms is
therefore better read as two similar *false-positive rates* than as two
measurements of a shared underlying detection ability.

Marginal flag rates also differ sharply — Haiku+Sonnet flags 57% of vulnerable
and 43% of fixed sides; Qwen flags 14% and 29%. The arms have very different
operating points and still produce the same PFA, which is only possible if PFA
is being driven by chance coincidence of two loosely-related flags.

### 4.6 Generation-failure rate is largely mismeasured

The Judge rubric's step 1 fires when **either** implementation is incoherent.
A `degenerate_generation` verdict therefore does not necessarily indicate a
Generator failure — it fires just as readily when the *reference snippet* is a
broken extraction (`PILOT_INSIGHTS.md` Finding 1: brace-matching landing on the
wrong function or a nested block).

Both judge calls see the **same** candidate and differ only in the reference, so
agreement across them identifies the culprit. Re-tokenizing every candidate
against the serving cap then separates a third cause:

| | Cases | Share |
|---|---|---|
| Pooled `degenerate_generation` (either side) | 34/391 | 8.7% |
| ├ **one** side only → reference-side artifact | 27/391 | 6.9% |
| └ **both** sides | 7/391 | 1.8% |
| &nbsp;&nbsp;&nbsp;&nbsp;├ output truncated at the 2048-token cap → **harness artifact** | 4/391 | 1.0% |
| &nbsp;&nbsp;&nbsp;&nbsp;└ **genuine model failure** | **3/391** | **0.8%** |

74% of the one-sided verdicts explicitly fault the reference in their rationale
(e.g. `C_104__1`: *"the reference implementation is incomplete and only includes
a small fragment of code (an error handling snippet with a `goto cleanup`
label)"*).

The truncation row is a **configuration defect in this experiment, not a
property of the model**: exactly 4 candidates (`C_588__3`, `C_588__4`,
`C_595__0`, `C_601__0`) emitted exactly 2048 tokens — the `--gen-max-tokens`
ceiling — and were cut off mid-function, which the Judge then correctly called
incoherent (`C_601__0`: *"appears to be cut off mid-function"*). All 4 fall in
the both-sides bucket, and no other case in the corpus reached the cap. A rerun
should raise `--gen-max-tokens` to ~4096; these 4 cases are the only ones
affected.

**Consequences.** Qwen3-32B's genuine generation-failure rate is **0.8%**
(3/391), not the 8.7% pooled figure — an order of magnitude lower. Separately,
~7% of cases stamped `extraction_status: "ok"` still carry a corrupt reference,
so the extraction pipeline's ~49% clean rate is optimistic. Both the 8.7% here
and the 7.1% reported for the Haiku arm conflate these causes; the metric should
be reported decomposed.

**The headline metrics are unaffected.** `compute_metrics.py` already excludes
every `degenerate_generation` case from `n_scored` (357 = 391 − 34), so all four
truncated cases sit outside the PFA, Pairwise Ranking, and ROC-AUC figures in
§4.1. Judge-side serving health is clean: **782/782** judge calls returned
`finish_reason: "stop"`, and there were zero empty generations.

---

## 5. Interpretation

The result is a **NO-GO for the method in its current formulation**, now
established at corpus scale rather than on 13 cases.

The mechanism is a signal-to-noise failure, not a model failure. A CVE fix is
frequently a single added bounds check. An LLM writing a Linux-kernel or
Chromium function from a paragraph of prose produces something structurally
unlike the real code — different helpers, different locking discipline,
different error paths, different types. The Judge sees many genuine behavioral
differences, is asked whether any is security-relevant, and reasonably answers
yes — including about the patched code, 44% of the time. The one difference that
*is* the CVE is buried among dozens that are not. §4.3(c) shows the consequence
quantitatively: the reference contributes little to the verdict.

What this run adds beyond confirming the number is **where not to spend effort
next**. Model capability is now a poor explanation: a 32B model in both roles
reproduced Haiku+Sonnet's result. Combined with the earlier finding that
supplying the Generator with the real masked source file also failed to help
(`reports/ablation_report.md`), two of the three obvious levers — better model,
more context — are now measured and negative. The remaining lever is the one
not yet tried: **the comparison task itself**. The Judge is asked a binary
"is this security-relevant?" about a comparison saturated with unrelated
differences. A rubric that instead asks the narrow question — *does one side
lack a guard, check, or bound that the other has?*, ignoring everything else —
is a different experiment and is now cheap to run.

---

## 6. Threats to validity

1. **The arms differ in both roles simultaneously.** Generator and Judge were
   swapped together, so this experiment cannot attribute the (null) effect to
   either. A Qwen-generator + Claude-judge arm would isolate it.
2. **The matched subset is underpowered.** n = 13 (Fisher p = 1.000). No
   per-model quality claim is supportable; only the null result is.
3. **The Claude arm's models are unpinned aliases** (`haiku`, `sonnet` in the
   agent frontmatter), not version-pinned identifiers. Its numbers are not
   exactly reproducible. The Qwen arm is pinned (local weights, fixed seed,
   `temperature` 0/0.2) — though vLLM continuous batching still makes outputs
   only approximately deterministic under concurrency.
4. **Single run, single seed.** No variance estimate across repeated runs; the
   CIs above are binomial only and do not capture run-to-run variation.
5. **Ground truth is commit-level, not function-level.** A case is labeled
   vulnerable because the CVE fix commit touched that function — not because
   each function was individually verified to contain the vulnerability. Some
   "vulnerable" snippets are likely collateral edits.
6. **~6.9% of references are corrupt extractions** (§4.6), adding noise. Too
   small to explain a 16%-vs-60% gap, but it biases the metrics somewhat.
7. **Quantization.** Qwen3-32B was served 4-bit AWQ, not fp16. A full-precision
   run could differ, though not plausibly by the margin required here.
8. **One case excluded** (`C_1313__0`, oversize prompt), a 0.26% coverage loss.
9. **A generation cap of 2048 tokens truncated 4 candidates** (§4.6). Those
   cases are excluded from all headline metrics as `degenerate_generation`, so
   the reported figures are unaffected — but the raw generation-failure rate is
   inflated by this harness setting, and a rerun should use ~4096.

---

## 7. Reproduction

```bash
git checkout docstring-leakage-audit-and-context-ablation

bash scripts/serve_qwen.sh                                    # vLLM + Qwen3-32B-AWQ, 1x RTX 4090
python3 scripts/run_cases_local.py --run qwen_full --concurrency 8   # 391 cases, ~16 min
python3 scripts/compute_metrics.py qwen_full                  # -> reports/qwen_full_report.md
python3 scripts/analyze_degenerate.py qwen_full               # -> the §4.6 decomposition
```

| File | Role |
|---|---|
| `scripts/serve_qwen.sh` | starts the local vLLM server (detached; `--small` fallback sizing) |
| `scripts/agent_prompts.py` | loads Generator/Judge prompts from `.claude/agents/*.md`; emits `prompt_sha` |
| `scripts/run_cases_local.py` | the driver — 1 generator call + 2 independent judge calls per case |
| `scripts/analyze_degenerate.py` | splits `degenerate_generation` into generator- vs reference-caused |
| `scripts/compute_metrics.py` | **unmodified** — the Qwen records use the existing result schema |

Information isolation was verified independently of the in-code guard: the
constructed Generator prompt was checked against all 392 eligible cases for any
≥25-character line shared with either snippet, and for the presence of
`cve_id` / `repo` / `changed_file`. Three matches surfaced and were all confirmed
benign — long C++ return types (e.g.
`std::vector<std::unique_ptr<ChooserContextBase::Object>>`) that appear in the
docstring's `Returns:` section and therefore necessarily also in the code. No
snippet body and no CVE metadata reaches the Generator.

The Claude arm (`.claude/`, `scripts/run_batch.ps1`, `results/pilot/`,
`results/ablation_*/`) was not modified; this arm is purely additive and both
remain runnable.
