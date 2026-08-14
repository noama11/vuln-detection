"""Evaluate the improved method arms against the published one.

Compares, on the same corpus and the same model:
  - the published method               (results/qwen_full/, 5-way taxonomy)
  - single-candidate guard contrast    (2026-08-19, narrow question, K=1)
  - consensus guard contrast           (this arm, narrow question, K=5)

Primary metric is directional accuracy with an unambiguous 50% chance line, not
Paired Flag Accuracy (whose chance level is 25% - see experiments/FINDINGS.md).
Ties are reported as coverage, never folded into the numerator.

Usage: python3 experiments/2026-08-20_consensus-guard/report.py
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "experiments" / "common"))

import paired_eval as E  # noqa: E402
from cve_taxonomy import classify, is_anticipatable  # noqa: E402
from data import load_cases, load_records  # noqa: E402

# (label, results dir, score function on one judge-call dict)
ARMS = [
    ("published method (5-way taxonomy)", ROOT / "results" / "qwen_full",
     lambda j: -j["score"]),          # judge score is inverse: lower = worse
    ("guard contrast, K=1", ROOT / "experiments" / "2026-08-19_guard-contrast"
     / "results" / "guard_contrast", lambda j: j["reference_exposure"]),
    ("consensus guard, K=5", HERE / "results" / "consensus_k5",
     lambda j: j["target_exposure"]),
]


def pct(x, nd=1):
    return "n/a" if x is None else f"{x * 100:.{nd}f}%"


def fmt(s):
    ci = f"[{pct(s['ci'][0])}, {pct(s['ci'][1])}]" if s.get("ci") else "n/a"
    p = s["p_value"]
    star = "" if p is None else (" ***" if p < 0.001 else " **" if p < 0.01
                                 else " *" if p < 0.05 else "")
    pv = "n/a" if p is None else (f"{p:.4f}" if p >= 1e-4 else f"{p:.1e}")
    return (f"| {s['label']} | {s['n']} | {s['n_decided']} | {pct(s['coverage'])} | "
            f"**{pct(s['accuracy'])}**{star} | {ci} | {pv} |")


def load_arm(path):
    recs = load_records(path)
    return list(recs.values())


def main():
    cases = load_cases()
    out = ["# Improving the method — results", "",
           "Same corpus, same model, same generator prompt. The premise is intact "
           "throughout: the Generator sees only `{language, docstring}`, the Judge "
           "sees one reference at a time and is never told which, and no supervised "
           "labels enter the detector.", "",
           "**Primary metric is directional accuracy**: given the same "
           "candidate(s), does the vulnerable reference score higher than the fixed "
           "one? Chance is exactly 50% on the decided subset. Ties are reported as "
           "coverage, never counted as either successes or failures. This replaces "
           "Paired Flag Accuracy, whose chance level is 25% and which requires one "
           "specific category out of five (see `experiments/FINDINGS.md`).", "",
           "| Arm | n | decided | coverage | accuracy | 95% CI | p (vs 50%) |",
           "|---|---|---|---|---|---|---|"]

    loaded = []
    for label, path, score_fn in ARMS:
        recs = load_arm(path)
        if not recs:
            out.append(f"| {label} | *not yet run* | | | | | |")
            continue
        loaded.append((label, recs, score_fn))
        out.append(fmt(E.summarise(recs, score_fn, label)))

    out.append("\n`*` p<0.05  `**` p<0.01  `***` p<0.001, exact two-sided binomial "
               "against 50%. CIs are CVE-clustered bootstraps (10k resamples).")

    # ------------------------------------------------- pre-registered tests
    cons = load_arm(HERE / "results" / "consensus_k5")
    if cons:
        out += ["", "## The two pre-registered tests", "",
                "Both were fixed in `PRE_REGISTRATION.md` before these records "
                "existed. Two tests, so the Bonferroni-corrected threshold is "
                "p < 0.025.", "",
                "| # | hypothesis | decided | coverage | accuracy | 95% CI | p |",
                "|---|---|---|---|---|---|---|"]
        tests = [
            ("H1 primary", "consensus exposure of the target",
             lambda j: j["target_exposure"]),
            ("H2 secondary", "net exposure (target - consensus control)",
             lambda j: j.get("net_exposure",
                             j["target_exposure"] - j.get("consensus_exposure", 0))),
        ]
        for tag, desc, fn in tests:
            s = E.summarise(cons, fn, desc)
            ci = f"[{pct(s['ci'][0])}, {pct(s['ci'][1])}]" if s.get("ci") else "n/a"
            p = s["p_value"]
            pv = "n/a" if p is None else (f"{p:.4f}" if p >= 1e-4 else f"{p:.1e}")
            verdict = "" if p is None else (" **PASSES**" if p < 0.025 else " (n.s.)")
            out.append(f"| {tag} | {desc} | {s['n_decided']} | {pct(s['coverage'])} | "
                       f"**{pct(s['accuracy'])}** | {ci} | {pv}{verdict} |")

        out += ["", "And the pre-registered stratified prediction (the "
                "dissociation), on H1:", "",
                "| stratum | decided | accuracy | 95% CI | p |", "|---|---|---|---|---|"]
        for nm, pred in [("anticipatable defensive step", True),
                         ("domain-specific / other", False)]:
            sub = [r for r in cons if r["case_id"] in cases
                   and is_anticipatable(cases[r["case_id"]]) == pred]
            if not sub:
                continue
            s = E.summarise(sub, lambda j: j["target_exposure"], nm)
            ci = f"[{pct(s['ci'][0])}, {pct(s['ci'][1])}]" if s.get("ci") else "n/a"
            p = s["p_value"]
            pv = "n/a" if p is None else f"{p:.4f}"
            out.append(f"| {nm} | {s['n_decided']} | {pct(s['accuracy'])} | {ci} | {pv} |")
        out.append("")

    # ---------------------------------------------------------------- strata
    out += ["", "## Where it works: stratified by what the fix does", "",
            "The method's hypothesis is that an independent implementation written "
            "from the specification contains a defensive step the vulnerable version "
            "omits. That is only possible when the omitted step is one such an author "
            "could plausibly write — a bounds check, a null check, an initialisation. "
            "It cannot work when the fix is a domain-specific correction no reader of "
            "the spec could anticipate. The split is lexical, computed from the diff "
            "with no model involved (`experiments/common/cve_taxonomy.py`), so it "
            "cannot be contaminated by the model being evaluated.", ""]

    for label, recs, score_fn in loaded:
        anti = [r for r in recs if r["case_id"] in cases
                and is_anticipatable(cases[r["case_id"]])]
        rest = [r for r in recs if r["case_id"] in cases
                and not is_anticipatable(cases[r["case_id"]])]
        if not anti or not rest:
            continue
        out += [f"**{label}**", "",
                "| stratum | n | decided | accuracy | 95% CI | p |",
                "|---|---|---|---|---|---|"]
        for nm, sub in [("fix adds an anticipatable defensive step", anti),
                        ("fix is domain-specific / other", rest)]:
            s = E.summarise(sub, score_fn, nm)
            out.append(fmt(s).replace(f"| {nm} |", f"| {nm} |"))
        out.append("")

    # by fix category, best arm only
    if loaded:
        label, recs, score_fn = loaded[-1]
        out += [f"By fix category (**{label}**):", "",
                "| fix category | n | decided | accuracy |", "|---|---|---|---|"]
        buckets = {}
        for r in recs:
            c = cases.get(r["case_id"])
            if c:
                buckets.setdefault(classify(c), []).append(r)
        for cat, sub in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
            s = E.summarise(sub, score_fn, cat)
            out.append(f"| {cat} | {s['n']} | {s['n_decided']} | "
                       f"{pct(s['accuracy'])} |")
        out.append("")

    # ------------------------------------------------------- coverage curve
    if loaded:
        label, recs, score_fn = loaded[-1]
        out += ["## Coverage–accuracy trade-off", "",
                "Abstention is legitimate for a triage tool: a detector that is "
                "reliable on the cases it is confident about is useful even if it is "
                "at chance overall. Each row demands a larger gap between the two "
                "sides before the detector will answer.", "",
                f"**{label}**", "",
                "| required score margin | cases answered | coverage | accuracy | p |",
                "|---|---|---|---|---|"]
        for row in E.coverage_curve(recs, score_fn, margins=(1, 2, 3, 4, 5, 6)):
            p = row["p"]
            pv = "n/a" if p is None else (f"{p:.4f}" if p >= 1e-4 else f"{p:.1e}")
            out.append(f"| >= {row['margin']} | {row['n_decided']} | "
                       f"{pct(row['coverage'])} | {pct(row['accuracy'])} | {pv} |")
        out.append("")

    path = HERE / "report.md"
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}\n")
    print("\n".join(out))


if __name__ == "__main__":
    main()
