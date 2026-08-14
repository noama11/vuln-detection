"""WP3 report - every baseline and the method in one table, same paired metric.

B3 (the trivial predictors) needs no inference and is computed here directly.
The one that matters is `shorter side is vulnerable`: a CVE fix usually *adds* a
guard, so function length alone is a corpus artefact that any method must beat
to have shown anything.

Usage: python3 experiments/2026-08-16_baselines/report.py
"""
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "experiments" / "common"))

import metrics as M  # noqa: E402
from data import Pair, load_cases, load_records, scored, to_pairs  # noqa: E402

SECURITY = "security_vulnerability_concern"
CLEAN = "equivalent_implementation_difference"

ARMS = [
    ("Method (spec reconstruction)", ROOT / "results" / "qwen_full",
     "generate from spec, judge twice"),
    ("B1 direct prompting", HERE / "results" / "direct",
     "ask the same model 'is this vulnerable?'"),
    ("B1s direct + spec", HERE / "results" / "direct_spec",
     "same, with the docstring supplied"),
    ("B2 flawfinder", HERE / "results" / "flawfinder",
     "conventional static analyser"),
]


def pct(x, nd=1):
    return "n/a" if x is None else f"{x * 100:.{nd}f}%"


def synthetic(cases, name, decide, seed=1234):
    """Build Pair objects from a rule instead of a model. `decide(case)` returns
    (flag_vulnerable, flag_fixed, score_vulnerable, score_fixed)."""
    rng = random.Random(seed)
    pairs = []
    for cid, c in sorted(cases.items()):
        fv, ff, sv, sf = decide(c, rng)
        pairs.append(Pair(case_id=cid, cve_id=c["cve_id"], repo=c["repo"],
                          language=c["language"], score_v=sv, score_f=sf,
                          cat_v=SECURITY if fv else CLEAN,
                          cat_f=SECURITY if ff else CLEAN, degenerate=False))
    return name, pairs


def trivial_baselines(cases):
    def lines(s):
        return len((s or "").splitlines())

    out = []
    out.append(synthetic(cases, "B3 always flag",
                         lambda c, r: (True, True, 1, 1)))
    out.append(synthetic(cases, "B3 never flag",
                         lambda c, r: (False, False, 10, 10)))
    out.append(synthetic(cases, "B3 coin flip (independent, p=0.5)",
                         lambda c, r: (r.random() < .5, r.random() < .5,
                                       r.randint(1, 10), r.randint(1, 10))))
    # A CVE fix usually adds a guard, so the vulnerable side is usually shorter.
    # This uses no semantics at all - only line count.
    out.append(synthetic(
        cases, "B3 shorter side is vulnerable",
        lambda c, r: (lines(c["vulnerable_snippet"]) < lines(c["fixed_snippet"]),
                      lines(c["fixed_snippet"]) < lines(c["vulnerable_snippet"]),
                      min(10, max(1, lines(c["vulnerable_snippet"]) // 10 + 1)),
                      min(10, max(1, lines(c["fixed_snippet"]) // 10 + 1)))))
    out.append(synthetic(
        cases, "B3 longer side is vulnerable",
        lambda c, r: (lines(c["vulnerable_snippet"]) > lines(c["fixed_snippet"]),
                      lines(c["fixed_snippet"]) > lines(c["vulnerable_snippet"]),
                      min(10, max(1, 10 - lines(c["vulnerable_snippet"]) // 20)),
                      min(10, max(1, 10 - lines(c["fixed_snippet"]) // 20)))))
    return out


def row(label, desc, pairs):
    s = M.summary(pairs)
    a, fr = s["afc"], s["flag_rates"]
    ci = M.cluster_bootstrap(pairs, M.pfa, n_boot=2000)
    ci_s = f"[{pct(ci['lo'])}, {pct(ci['hi'])}]" if ci else "n/a"
    return (f"| {label} | {desc} | {s['n_scored']} | **{pct(s['pfa'])}** | {ci_s} | "
            f"{pct(a['tie_corrected'])} | {s['roc_auc']:.3f} | "
            f"{pct(fr['vulnerable'])} / {pct(fr['fixed'])} |")


def main():
    cases = load_cases()
    out = ["# WP3 — Baselines", "",
           "Every row is scored with the identical paired metric on the identical "
           "case set: a case counts only when the vulnerable side is flagged "
           "`security_vulnerability_concern` **and** the fixed side is not. "
           "CIs are CVE-clustered bootstraps (2000 resamples).", "",
           "| Arm | What it does | n scored | PFA | 95% CI | 2AFC | ROC-AUC | "
           "flag rate vuln / fixed |",
           "|---|---|---|---|---|---|---|---|"]

    present = []
    for label, path, desc in ARMS:
        pairs = to_pairs(load_records(path))
        if not pairs:
            out.append(f"| {label} | {desc} | *not yet run* | | | | | |")
            continue
        present.append((label, pairs))
        out.append(row(label, desc, pairs))
    for name, pairs in trivial_baselines(cases):
        present.append((name, pairs))
        out.append(row(name, "no semantics", pairs))

    out.append("\n## Reading the table\n")
    by = dict(present)
    method = by.get("Method (spec reconstruction)")
    coin = by.get("B3 coin flip (independent, p=0.5)")

    out.append(
        "### Paired Flag Accuracy has a chance level of 25%, not 0%\n\n"
        "This is the single most important thing WP3 establishes, and it "
        "invalidates the project's pre-registered decision bands.\n\n"
        "A detector that flags each side independently with probability *p* scores\n\n"
        "> PFA = P(flag vulnerable) x P(not flag fixed) = p(1 - p)\n\n"
        "which is maximised at p = 0.5, giving **PFA = 25%** while using no "
        "information about the code whatsoever. The `always flag` and `never flag` "
        "rows score 0% not because they are worse detectors but because PFA "
        "punishes any detector that does not vary its answer — the metric rewards "
        "*asymmetry between the two calls*, and a coin flip supplies asymmetry for "
        "free.\n\n"
        "The pre-registered bands (>=80% GO, 60-80% expand, <60% NO-GO, "
        "`HANDOFF.md` s1) were written as though chance were 0%. Against a true "
        "chance level of 25%, the 60% floor is not 'somewhat above chance' but "
        "roughly the midpoint between chance and perfect — a far more demanding bar "
        "than intended. The paper should state the chance level explicitly and "
        "report every PFA against it.")

    if method is not None and coin is not None:
        mp, cp = M.pfa(method), M.pfa(coin)
        out.append(
            f"\n### The method scores below chance on its primary metric\n\n"
            f"Method **{pct(mp)}** vs coin flip **{pct(cp)}** (analytic chance 25.0%). "
            "The method is not merely failing to reach its target; it is below what a "
            "random detector achieves.\n\n"
            "This replaces the write-up's section 4.3(c) argument, which reached a "
            "similar conclusion by multiplying marginal flag rates under an "
            "independence assumption it simultaneously denied. The comparison here "
            "needs no such assumption — it is a directly measured random baseline on "
            "the same cases.\n\n"
            "**The two nulls answer different questions and both belong in the paper:**\n\n"
            f"- *Permutation null* (WP1, {pct(0.174)}): holding the judge's own flag "
            "rates and its between-call correlation fixed, does the label matter? "
            "Answer: no — 16.0% is inside that null. The method extracts no label "
            "information.\n"
            f"- *Coin-flip baseline* (this table, {pct(cp)}): could a detector with no "
            "information do better by simply operating at a different point? Answer: "
            "yes, substantially. The method's operating point is also worse than random.")

    beaten = [(n, M.pfa(p)) for n, p in present
              if method is not None and n != "Method (spec reconstruction)"
              and M.pfa(p) is not None and M.pfa(p) >= M.pfa(method)]
    if beaten:
        out.append("\n**Every baseline that matches or beats the method:**\n")
        for n, v in sorted(beaten, key=lambda kv: -kv[1]):
            out.append(f"- {n}: {pct(v)}")

    ln, lng = by.get("B3 shorter side is vulnerable"), by.get("B3 longer side is vulnerable")
    if ln is not None and lng is not None:
        out.append(
            f"\n### A length artefact, in the unexpected direction\n\n"
            f"`longer side is vulnerable` reaches **{pct(M.pfa(lng))}** using nothing "
            f"but line counts, against **{pct(M.pfa(ln))}** for the opposite rule. "
            "74.2% of pairs have identical line counts, so among the pairs that differ "
            "the vulnerable side is the longer one about five times out of six.\n\n"
            "That is the reverse of the intuition that a fix adds a guard, and it is "
            "**partly an extraction defect rather than a property of CVE fixes**: 93 of "
            "392 vulnerable snippets are brace-unbalanced (they over-run the target "
            "function and trail into the next one), against 3 of 392 on the fixed side "
            "— the vulnerable-side mirror of the fixed-side bug in `PILOT_INSIGHTS.md` "
            "Finding 1, and previously undocumented. See the threats note in "
            "`experiments/2026-08-17_spec-provenance/`. Restricting to cleanly "
            "extracted cases moves the method's PFA only from 16.0% to 15.8%, so this "
            "does not explain the null — but it does mean any length-correlated "
            "predictor on this corpus is partly measuring the extractor.")

    ff = by.get("B2 flawfinder")
    if ff is not None:
        s = M.summary(ff)
        out.append(f"\n**flawfinder caveat.** It flags only "
                   f"{pct(s['flag_rates']['vulnerable'])} of vulnerable sides: the "
                   "snippets are bare functions without headers, macros or types, so "
                   "its pattern rules mostly find nothing. This is a fair measurement "
                   "of *a static analyser applied to this corpus as extracted*, not of "
                   "flawfinder on a complete build tree — state it that way in the paper.")

    path = HERE / "report.md"
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}\n")
    print("\n".join(out))


if __name__ == "__main__":
    main()
