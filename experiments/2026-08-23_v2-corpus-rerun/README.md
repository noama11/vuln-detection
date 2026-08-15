# The method on the corrected corpus (`v2-corpus-rerun`)

**Objective**: close `RESEARCH_LOG.md` open thread #1 — re-run the headline arm
on the corrected 626-case corpus produced by
`experiments/2026-08-22_extraction-v2/`, so that every number in chapters 4–12
moves from *provisional* to *final*.

Pre-registered in `RESEARCH_LOG.md` ch. 14 **before launch**. The prediction on
record: PFA lands in 12–20% with a CVE-clustered CI excluding 25%, i.e. the null
holds and tightens.

## Why this run and not another variant

This is the only remaining experiment that changes the *precision* of the
project's central claim rather than adding a further failed reformulation.

| | published (`qwen_full`) | this arm |
|---|---:|---:|
| corpus | `cases/` (`d98dcc64782d`) | `cases_v2/` (`b60b2d62fbd0`) |
| cases run | 391 | 626 |
| share of the 792-case dataset | 49% | 79% |
| unique CVEs | 302 | 453 |
| vulnerable side a clean single function | 163 (42%) | 626 (100%) |
| fixed side clean | 390 (99.5%) | 626 (100%) |

The published arm compared each candidate against a **contaminated** pre-patch
reference and a **clean** post-patch one — a one-sided defect running in the same
direction as the result. That asymmetry is gone here: both sides are
brace-matched by the same code path.

## Configuration

Identical to the published arm, so the corpus is the only variable.

| | |
|---|---|
| model | `qwen3-32b-awq` (Qwen3-32B-AWQ, local vLLM, RTX 4090) |
| seed | 1234 |
| gen / judge temperature | 0.2 / 0.0 |
| thinking | off |
| `prompt_sha` | `1de29ae28c7d` — unchanged from the published arm |
| `corpus_sha` | `b60b2d62fbd0` — stamped into every record |

Premise intact: the Generator receives only `{language, docstring}`; the Judge
sees one reference at a time and is never told which; no supervised labels.

## Rerun

```bash
bash scripts/serve_qwen.sh                                  # local vLLM, ~4 min warmup
python3 scripts/run_cases_local.py \
    --run qwen_v2 \
    --cases-dir experiments/2026-08-22_extraction-v2/cases_v2 \
    --seed 1234 --concurrency 8                             # 626 cases, ~30 min
mv results/qwen_v2 experiments/2026-08-23_v2-corpus-rerun/results/
python3 experiments/2026-08-23_v2-corpus-rerun/report.py    # -> report.md
```

Results are relocated into this arm after the run so that `results/` stays as
published; the runner writes to `results/<run>/` by construction.

## Analysis plan (fixed in advance)

- **Primary**: PFA on the 539 non-duplicate cases, CVE-clustered bootstrap CI
  over 453 CVEs, 10k resamples. Chance = 25%.
- **Matched subset** — the 344 cases present in **both** corpora. Same cases,
  same CVEs, same prompts, same seed; only the snippets are repaired. This
  isolates the extraction fix from the corpus expansion and is the cleanest
  single comparison available in the project.
- **Descriptive only**: PFA including the 87 `duplicate_of` cases, directional
  accuracy, ROC-AUC, per-side degenerate-generation rate.

No subgroup is promoted to a headline. Chapters 10 and 12 both produced a
marginal single-run result that failed to replicate; one pre-registered test is
the discipline that follows from that.
