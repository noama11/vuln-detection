"""Chapter 12 report — defensive reconstruction with explicit guard claims.

Pre-registered (RESEARCH_LOG.md ch. 12): primary is directional accuracy on the
severity-weighted omission score, chance 50%, ties reported as coverage, one
test, p < 0.05. The anticipatable / domain-specific split is reported as a
secondary and is not claimed.

Usage: python3 experiments/2026-08-21_defensive-claims/report.py
"""
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "experiments" / "common"))

import paired_eval as E  # noqa: E402
from cve_taxonomy import classify, is_anticipatable  # noqa: E402
from data import load_cases, load_records  # noqa: E402

SCORES = [
    ("severity-weighted omissions (pre-registered primary)", lambda j: j["score"]),
    ("count of omissions", lambda j: j["n_omits"]),
    ("max single-omission severity", lambda j: j.get("max_severity", 0)),
]


def pct(x, nd=1):
    return "n/a" if x is None else f"{x * 100:.{nd}f}%"


def row(s):
    ci = f"[{pct(s['ci'][0])}, {pct(s['ci'][1])}]" if s.get("ci") else "n/a"
    p = s["p_value"]
    star = "" if p is None else (" ***" if p < 0.001 else " **" if p < 0.01
                                 else " *" if p < 0.05 else "")
    pv = "n/a" if p is None else (f"{p:.4f}" if p >= 1e-4 else f"{p:.1e}")
    return (f"| {s['label']} | {s['n']} | {s['n_decided']} | {pct(s['coverage'])} | "
            f"**{pct(s['accuracy'])}**{star} | {ci} | {pv} |")


def main():
    cases = load_cases()
    recs = list(load_records(HERE / "results" / "defensive_claims").values())
    if not recs:
        print("no records yet")
        return 1

    primary = SCORES[0][1]
    out = ["# Chapter 12 — Defensive reconstruction with explicit guard claims", "",
           "Premise intact: the Generator sees only `{language, docstring}`, the "
           "Judge sees one reference at a time and is never told which, no "
           "supervised labels. What changed is the generator's *instruction* "
           "(hardened rather than faithful, still spec-only) and the judge's "
           "*task* (per-claim verification rather than open-ended comparison).", "",
           "## Pre-registered primary test", "",
           "| score | n | decided | coverage | accuracy | 95% CI | p |",
           "|---|---|---|---|---|---|---|",
           row(E.summarise(recs, primary, SCORES[0][0])), ""]

    out += ["## Alternative scores from the same records", "",
            "Reported for completeness. These are **not** pre-registered; with "
            "three additional rules the corrected threshold is p < 0.0125, and any "
            "of them that looks good is a hypothesis for a fresh run, not a "
            "result — the lesson of chapters 10 and 11.", "",
            "| score | n | decided | coverage | accuracy | 95% CI | p |",
            "|---|---|---|---|---|---|---|"]
    for label, fn in SCORES[1:]:
        out.append(row(E.summarise(recs, fn, label)))
    out.append("")

    # --------------------------------------------------------------- strata
    out += ["## Secondary: stratified by what the fix does", "",
            "Split is lexical, from the diff, no model involved "
            "(`experiments/common/cve_taxonomy.py`). The domain-specific stratum "
            "is the control: the method *cannot* work there, because no reader of "
            "the specification could anticipate the fix.", "",
            "| stratum | n | decided | coverage | accuracy | 95% CI | p |",
            "|---|---|---|---|---|---|---|"]
    for nm, pred in [("fix adds an anticipatable defensive step", True),
                     ("fix is domain-specific / other (control)", False)]:
        sub = [r for r in recs if r["case_id"] in cases
               and is_anticipatable(cases[r["case_id"]]) == pred]
        if sub:
            out.append(row(E.summarise(sub, primary, nm)))
    out.append("")

    out += ["By fix category:", "",
            "| fix category | n | decided | accuracy | p |", "|---|---|---|---|---|"]
    buckets = {}
    for r in recs:
        c = cases.get(r["case_id"])
        if c:
            buckets.setdefault(classify(c), []).append(r)
    for cat, sub in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        s = E.summarise(sub, primary, cat)
        p = s["p_value"]
        pv = "n/a" if p is None else f"{p:.3f}"
        out.append(f"| {cat} | {s['n']} | {s['n_decided']} | "
                   f"{pct(s['accuracy'])} | {pv} |")
    out.append("")

    # ------------------------------------------------------ coverage curve
    out += ["## Coverage–accuracy trade-off", "",
            "| required score margin | answered | coverage | accuracy | p |",
            "|---|---|---|---|---|"]
    for r in E.coverage_curve(recs, primary, margins=(1, 2, 4, 6, 8, 10)):
        p = r["p"]
        pv = "n/a" if p is None else f"{p:.4f}"
        out.append(f"| >= {r['margin']} | {r['n_decided']} | {pct(r['coverage'])} | "
                   f"{pct(r['accuracy'])} | {pv} |")
    out.append("")

    # ------------------------------------------------------- diagnostics
    nclaims = [r["n_claims"] for r in recs]
    vv = Counter()
    for r in recs:
        for side in ("judge_vs_vulnerable", "judge_vs_fixed"):
            for it in r[side].get("items", []):
                vv[it["verdict"]] += 1
    tot = sum(vv.values()) or 1
    mv = sum(r["judge_vs_vulnerable"]["score"] for r in recs) / len(recs)
    mf = sum(r["judge_vs_fixed"]["score"] for r in recs) / len(recs)
    ov = sum(r["judge_vs_vulnerable"]["n_omits"] for r in recs) / len(recs)
    of = sum(r["judge_vs_fixed"]["n_omits"] for r in recs) / len(recs)

    out += ["## Diagnostics — did the mechanism behave as designed?", "",
            f"- Guard claims per case: mean **{sum(nclaims)/len(nclaims):.1f}**, "
            f"min {min(nclaims)}, max {max(nclaims)}",
            f"- Verdict mix over all {tot} claim checks: " +
            ", ".join(f"**{k}** {pct(v/tot)}" for k, v in vv.most_common()),
            f"- Mean severity-weighted score: vulnerable **{mv:.2f}**, "
            f"fixed **{mf:.2f}**, delta **{mv-mf:+.2f}**",
            f"- Mean omissions per case: vulnerable **{ov:.2f}**, fixed **{of:.2f}**",
            "",
            "The `not_applicable` share is the load-bearing number: if it is near "
            "zero the judge is counting invented guards as real omissions, and if "
            "it is near one the checklist is not engaging with the reference at "
            "all. The delta is the detection signal — it must be clearly positive "
            "for the method to work.", ""]

    path = HERE / "report.md"
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}\n")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
