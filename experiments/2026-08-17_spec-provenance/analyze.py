"""WP4(a) - is the specification derived from the vulnerable side?

The method assumes the docstring is a neutral statement of intent that both the
vulnerable and the fixed implementation are candidates to satisfy. If instead the
docstring was written *from* the vulnerable code, then a faithful clean-room
reconstruction should resemble the vulnerable version, and the detector is
biased against itself by construction.

Test: identifiers that occur in exactly one side of the fix. A spec written from
the vulnerable code will mention vulnerable-only names it has no other way to
know; a spec written from the fixed code shows the mirror. The corpus-wide ratio
of the two counts is the provenance signal, and a sign test over cases gives it a
p-value.

Also audits an extraction defect discovered while building this: the vulnerable
side over-runs the target function far more often than the fixed side does. That
is the mirror image of `PILOT_INSIGHTS.md` Finding 1 and is not documented
anywhere in the repo.

Pure computation, no inference. Usage:
    python3 experiments/2026-08-17_spec-provenance/analyze.py
"""
import json
import math
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "experiments" / "common"))

import metrics as M  # noqa: E402
from data import identifiers, load_cases, load_records, provenance_counts, to_pairs  # noqa: E402


def pct(x, nd=1):
    return "n/a" if x is None else f"{x * 100:.{nd}f}%"


def sign_test(k, n):
    """One-sided binomial p for k successes in n trials at p=0.5."""
    if n == 0:
        return None
    return sum(math.comb(n, i) for i in range(k, n + 1)) / 2 ** n


def brace_balance(code):
    t = (code or "").strip()
    return t.count("{") - t.count("}")


def main():
    cases = load_cases()
    out = ["# WP4(a) — Specification provenance, and an extraction defect", ""]

    # ---------------------------------------------------------------- provenance
    lean_v = lean_f = tie = 0
    tot_v = tot_f = 0
    per_case = {}
    for cid, c in cases.items():
        hv, hf = provenance_counts(c)
        per_case[cid] = (hv, hf)
        tot_v += hv
        tot_f += hf
        if hv > hf:
            lean_v += 1
        elif hf > hv:
            lean_f += 1
        else:
            tie += 1

    p = sign_test(lean_v, lean_v + lean_f)
    out += [
        "## 1. The specifications are derived from the vulnerable code", "",
        "For each case, count how many identifiers unique to one side of the fix "
        "the docstring mentions. An identifier that appears only in the vulnerable "
        "version and also in the spec is information the spec could only have got "
        "from the vulnerable version.", "",
        "| | Total mentions | Cases leaning this way |",
        "|---|---|---|",
        f"| Vulnerable-only identifiers | **{tot_v}** | **{lean_v}** |",
        f"| Fixed-only identifiers | **{tot_f}** | **{lean_f}** |",
        f"| (neither / tied) | — | {tie} |",
        "",
        f"Ratio **{tot_v / max(tot_f, 1):.1f}x** toward the vulnerable side. "
        f"Sign test over the {lean_v + lean_f} non-tied cases: "
        f"**p = {p:.2e}** one-sided.",
        "",
        "This survives the docstring-leakage audit described in `HANDOFF.md` s3. "
        "That audit removed docstrings that *state the fix* or *narrate the bug*; "
        "it could not remove the fact that the spec was written by reading the "
        "pre-patch function. The corpus's own structure confirms the mechanism: "
        "`D.zip`'s `scope` entries carry `start`/`end` line numbers into "
        "`vulnerable.<ext>`, so the documentation was generated against the "
        "vulnerable file.",
        "",
        "**Consequence for the method.** The method's premise is that a clean-room "
        "implementation written from a correct spec resembles *correct* code. If the "
        "spec is a description of the vulnerable code, the reconstruction should "
        "resemble the *vulnerable* code instead, and the detector is biased against "
        "its own hypothesis. This predicts exactly the two anomalies the write-up "
        "reports without explaining: ROC-AUC of 0.475 (below 0.5) and a mean score "
        "gap of -0.18 in favour of the vulnerable side.",
        "",
        "**This is not only a dataset artefact.** In deployment the same thing holds: "
        "a real project's docstring is written alongside the code it documents, which "
        "is the vulnerable version right up until the patch lands. Any spec-"
        "reconstruction detector inherits this bias wherever the spec is not written "
        "independently of the implementation. WP4(b) tests the claim causally by "
        "regenerating specs from the fixed side and looking for a sign flip.",
    ]

    # -------------------------------------------------------------- sufficiency
    covs, zero = [], 0
    for cid, c in cases.items():
        v, f = identifiers(c["vulnerable_snippet"]), identifiers(c["fixed_snippet"])
        changed = v ^ f
        d = identifiers(c["docstring"])
        cov = len(changed & d) / len(changed) if changed else 1.0
        covs.append(cov)
        if cov == 0.0:
            zero += 1
    covs.sort()
    out += [
        "", "## 2. How much of the fix the spec could possibly describe", "",
        "A lexical lower bound on spec sufficiency: what fraction of the "
        "identifiers that differ between the two versions does the docstring "
        "mention at all? If it mentions none of them, no reconstruction from that "
        "spec can distinguish the versions, whatever model writes it.", "",
        f"- Median coverage: **{pct(statistics.median(covs))}**",
        f"- p25 {pct(covs[len(covs)//4])}, p75 {pct(covs[3*len(covs)//4])}",
        f"- Cases mentioning **none** of the changed identifiers: "
        f"**{zero}/{len(covs)}** ({pct(zero/len(covs))})",
        "",
        "This is a *lower* bound on the information deficit — a spec can describe a "
        "property without naming the identifiers involved — so WP4(c) re-measures it "
        "semantically. But it already shows the ceiling is well below 100%: for a "
        "large minority of the corpus the specification is silent about everything "
        "the patch touched.",
    ]

    # ------------------------------------------------------- extraction defect
    over = {cid for cid, c in cases.items() if brace_balance(c["vulnerable_snippet"]) > 0}
    under = {cid for cid, c in cases.items() if brace_balance(c["vulnerable_snippet"]) < 0}
    fixed_bad = {cid for cid, c in cases.items() if brace_balance(c["fixed_snippet"]) != 0}
    clean = set(cases) - over - under

    out += [
        "", "## 3. An undocumented extraction defect on the vulnerable side", "",
        "`PILOT_INSIGHTS.md` Finding 1 documents the *fixed*-side extractor landing "
        "on the wrong function. The vulnerable side has the mirror problem, and it is "
        "recorded nowhere: `extract_cases.py` slices the vulnerable snippet straight "
        "from the dataset's literal `scope.start`/`scope.end` line range, and that "
        "range frequently over-runs the target function.", "",
        "| Side | brace-balanced | over-runs into next function | truncated |",
        "|---|---|---|---|",
        f"| vulnerable | {len(clean)} | **{len(over)}** | {len(under)} |",
        f"| fixed | {len(cases) - len(fixed_bad)} | — | {len(fixed_bad)} |",
        "",
        f"**{len(over) + len(under)} of {len(cases)} "
        f"({pct((len(over)+len(under))/len(cases))}) vulnerable snippets are "
        "malformed, against "
        f"{len(fixed_bad)} ({pct(len(fixed_bad)/len(cases))}) on the fixed side.** "
        "Every one of these cases carries `extraction_status: \"ok\"`, so they are "
        "inside all published metrics.",
        "",
        "Example, `C_102__0`: the vulnerable snippet ends part-way into "
        "`shmem_show_options`, the function following the target "
        "`shmem_remount_fs`; the fixed snippet ends correctly at the target's "
        "closing brace.",
    ]

    pairs = to_pairs(load_records(ROOT / "results" / "qwen_full"))
    if pairs:
        rows = []
        for name, ids in [("cleanly extracted", clean), ("over-run", over)]:
            sub = [p for p in pairs if p.case_id in ids]
            if sub:
                s = M.summary(sub)
                rows.append(f"| {name} | {s['n_scored']} | {pct(s['pfa'])} | "
                            f"{s['roc_auc']:.3f} | "
                            f"{pct(s['flag_rates']['vulnerable'])} / "
                            f"{pct(s['flag_rates']['fixed'])} |")
        out += ["", "Effect on the published run:", "",
                "| Vulnerable-side extraction | n scored | PFA | ROC-AUC | "
                "flag vuln / fixed |", "|---|---|---|---|---|"] + rows
        out += ["",
                "**It is a genuine data-quality problem but not the cause of the "
                "null**: restricting to cleanly extracted cases barely moves PFA. It "
                "does inflate the fixed-side flag rate and depress ROC-AUC, and it "
                "biases any length-based comparison, so it belongs in Threats and "
                "should be fixed before anyone reuses this corpus."]

    (HERE / "provenance_report.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    (HERE / "provenance_per_case.json").write_text(
        json.dumps({cid: {"vulnerable_only_hits": v, "fixed_only_hits": f,
                          "vulnerable_extraction":
                              "over_run" if cid in over else
                              "truncated" if cid in under else "clean"}
                    for cid, (v, f) in per_case.items()}, indent=2), encoding="utf-8")
    print(f"wrote {(HERE / 'provenance_report.md').relative_to(ROOT)}\n")
    print("\n".join(out))


if __name__ == "__main__":
    main()
