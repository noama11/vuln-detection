# WP3 — Baselines

**Objective**: score the obvious alternatives on the identical cases with the
identical paired metric, so the null result is about *the task* and not just
about one method.

**What differs from the reference arm**: no reconstruction step. B1/B1s ask the
same local Qwen3-32B directly; B2 is a conventional static analyser; B3 is
computed arithmetic with no model at all. The judge rubric is not used, so these
carry their own `prompt_sha` (`5e14787b4aaa` for the direct detector) rather than
the published `1de29ae28c7d`.

**Rerun**:

```bash
bash scripts/serve_qwen.sh                                            # for B1/B1s
python3 experiments/2026-08-16_baselines/run.py --arms B1 B1s         # ~25 min
python3 experiments/2026-08-16_baselines/run.py --arms B2             # ~30 s, CPU only
python3 experiments/2026-08-16_baselines/report.py                    # B3 computed here
```

`flawfinder` comes from `pip install --user flawfinder` (2.0.20); it needs no
root and no build tree.

## The finding that matters

**Paired Flag Accuracy has a chance level of 25%, not 0%.** A detector flagging
each side independently with probability *p* scores `p(1-p)`, maximised at
p = 0.5. The measured coin flip lands at 31.4% and the method at **16.0%** — so
the method is below a random detector on its own primary metric.

This also means the pre-registered go/no-go bands (≥80% GO, 60–80% expand, <60%
NO-GO) were calibrated as though chance were zero. Against a true chance level of
25%, the 60% floor sits near the midpoint between chance and perfect, which is a
much more demanding bar than the plan intended. State the chance level explicitly
in the paper and report every PFA against it.

`always flag` and `never flag` both score 0% — not because they are worse
detectors than the coin flip, but because PFA rewards *asymmetry between the two
calls* and a constant predictor supplies none. That asymmetry sensitivity is
worth a sentence in the paper: it is why a metric that looks like accuracy does
not behave like one.

## Secondary findings

- **`longer side is vulnerable` reaches 21.4%** on line counts alone. 74% of
  pairs have identical line counts; among those that differ the vulnerable side
  is longer about five times in six. That is partly the extraction defect
  documented in `experiments/2026-08-17_spec-provenance/` — 93/392 vulnerable
  snippets over-run their function — so length-correlated predictors on this
  corpus are partly measuring the extractor.
- **flawfinder scores 2.8%**, flagging only 18.4% of vulnerable sides. The
  snippets are bare functions with no headers, macros or types, so its pattern
  rules mostly find nothing. Report it as *a static analyser applied to this
  corpus as extracted*, not as flawfinder's general capability.
