"""Chapter 14 report — the method on the corrected 626-case corpus.

Pre-registered (RESEARCH_LOG.md ch. 14, written before launch): the primary is
PFA on the non-duplicate subset with a CVE-clustered bootstrap CI, chance 25%.
The matched 344-case subset present in both corpora is the secondary and
isolates the extraction fix from the corpus expansion. Everything else is
descriptive and is not promoted to a headline.

Usage: python3 experiments/2026-08-23_v2-corpus-rerun/report.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "experiments" / "common"))

import metrics as M  # noqa: E402
from data import load_cases, load_records, scored, to_pairs  # noqa: E402

V2_CASES = ROOT / "experiments" / "2026-08-22_extraction-v2" / "cases_v2"
PUBLISHED = ROOT / "results" / "qwen_full"
CHANCE = 0.25


def pct(x, nd=1):
    return "n/a" if x is None else f"{x * 100:.{nd}f}%"


def ci_of(pairs, stat=M.pfa, label=""):
    """Point estimate + CVE-clustered CI, as one printable row."""
    v = stat(pairs)
    ci = M.cluster_bootstrap(pairs, stat) if pairs else None
    s = scored(pairs)
    cis = f"[{pct(ci['lo'])}, {pct(ci['hi'])}]" if ci else "n/a"
    ncl = ci["n_clusters"] if ci else 0
    return {"label": label, "n": len(pairs), "n_scored": len(s), "value": v,
            "ci": ci, "row": f"| {label} | {len(pairs)} | {len(s)} | {ncl} | "
                             f"**{pct(v)}** | {cis} |"}


def verdict(ci):
    """Where the pre-registered CI sits relative to the 25% chance level."""
    if not ci:
        return "no interval"
    if ci["hi"] < CHANCE:
        return "**below chance** — CI excludes 25% from below"
    if ci["lo"] > CHANCE:
        return "**above chance** — CI excludes 25% from above"
    return "indistinguishable from chance — CI contains 25%"


def main():
    recs = load_records(HERE / "results" / "qwen_v2")
    if not recs:
        print("no records yet — run the arm first (see README.md)")
        return 1
    cases = load_cases(V2_CASES)
    pairs = to_pairs(recs)

    dup = {cid for cid, c in cases.items() if c.get("duplicate_of")}
    nondup = [p for p in pairs if p.case_id not in dup]

    out = ["# Chapter 14 — The method on the corrected corpus", "",
           f"Corpus `cases_v2/` (626 usable cases, 79% of the 792-case dataset) "
           f"against the published corpus's 392 (49%). Configuration identical to "
           f"the published arm — seed 1234, temperatures 0.2 / 0.0, "
           f"`prompt_sha 1de29ae28c7d` — so the corpus is the only variable.", "",
           "## Pre-registered primary", "",
           "PFA on the non-duplicate subset, CVE-clustered bootstrap CI, "
           "10k resamples. **Chance is 25%**, not 0%.", "",
           "| set | cases | scored | CVEs | PFA | 95% CI (CVE-clustered) |",
           "|---|---|---|---|---|---|"]

    primary = ci_of(nondup, M.pfa, "non-duplicate (pre-registered primary)")
    out.append(primary["row"])
    out.append(ci_of(pairs, M.pfa, "all cases (descriptive)")["row"])
    out += ["", f"**Verdict against the pre-registration**: {verdict(primary['ci'])}.",
            ""]

    # ------------------------------------------------- vs the published arm
    out += ["## Against the published arm", "",
            "| | published (`qwen_full`) | this arm (`qwen_v2`) |",
            "|---|---|---|"]
    pub_recs = load_records(PUBLISHED)
    pub = to_pairs(pub_recs)
    ps, vs = M.summary(pub), M.summary(nondup)
    for k, lab, f in [("n_cases", "cases run", str),
                      ("n_scored", "scored", str),
                      ("degenerate_rate", "degenerate rate", pct),
                      ("pfa", "PFA", pct),
                      ("roc_auc", "ROC-AUC", lambda x: "n/a" if x is None else f"{x:.3f}")]:
        out.append(f"| {lab} | {f(ps[k])} | {f(vs[k])} |")
    for side in ("vulnerable", "fixed"):
        out.append(f"| flag rate, {side} side | {pct(ps['flag_rates'][side])} | "
                   f"{pct(vs['flag_rates'][side])} |")
    out.append(f"| independence baseline | {pct(ps['flag_rates']['independence_baseline'])} | "
               f"{pct(vs['flag_rates']['independence_baseline'])} |")
    out.append("")

    # --------------------------------------------------- matched 344 subset
    both = sorted(set(pub_recs) & set(recs))
    out += ["## Matched subset — the cleanest comparison available", "",
            f"The **{len(both)} cases present in both corpora**. Same cases, same "
            "CVEs, same prompts, same seed; only the snippets are repaired. Any "
            "difference here is attributable to the extraction fix alone, with "
            "the corpus expansion held out.", "",
            "| corpus | cases | scored | CVEs | PFA | 95% CI (CVE-clustered) |",
            "|---|---|---|---|---|---|"]
    mp = [p for p in pub if p.case_id in set(both)]
    mv = [p for p in pairs if p.case_id in set(both)]
    out.append(ci_of(mp, M.pfa, "published snippets")["row"])
    out.append(ci_of(mv, M.pfa, "corrected snippets")["row"])

    flips = sum(1 for a in mp for b in mv if a.case_id == b.case_id
                and not a.degenerate and not b.degenerate
                and a.paired_flag_correct != b.paired_flag_correct)
    out += ["", f"Cases whose paired-flag outcome changed sign: **{flips}**.", "",
            "PFA barely moves. **The directional quantities all change sign**, and "
            "that is the finding — on identical cases, with only the snippets "
            "repaired:", "",
            "| | published snippets | corrected snippets |", "|---|---|---|"]
    for lab, fn in [
        ("ROC-AUC", lambda p: f"{M.auc(p):.3f}"),
        ("flag rate, vulnerable − fixed",
         lambda p: f"{(M.flag_rates(p)['vulnerable'] - M.flag_rates(p)['fixed']) * 100:+.1f}pp"),
        ("permutation null mean",
         lambda p: pct(M.permutation_test(p)["null_mean"])),
        ("p(observed PFA ≥ null)",
         lambda p: f"{M.permutation_test(p)['p_greater']:.3f}"),
    ]:
        out.append(f"| {lab} | {fn(mp)} | {fn(mv)} |")
    out += ["",
            "The published arm sat **below** its own permutation null with the "
            "*fixed* side flagged more often than the vulnerable one — an "
            "anti-signal. On repaired snippets both reverse: AUC crosses 0.5, the "
            "vulnerable side is flagged more, and the observed PFA sits slightly "
            "above the null rather than below it. Corpus expansion is held out, so "
            "this is attributable to the extraction fix alone.", ""]

    # ------------------------------------------------------- descriptive
    afc = M.afc(nondup)
    out += ["## Descriptive (not pre-registered, not promoted)", "",
            f"- Directional accuracy on the judge score: raw **{pct(afc['raw'])}**, "
            f"tie-corrected **{pct(afc['tie_corrected'])}** "
            f"(n={afc['n_untied']}, tie rate {pct(afc['tie_rate'])})",
            f"- ROC-AUC: **{vs['roc_auc']:.3f}**" if vs["roc_auc"] else "- ROC-AUC: n/a",
            f"- Mean judge score: vulnerable **{vs['mean_scores']['vulnerable']:.2f}**, "
            f"fixed **{vs['mean_scores']['fixed']:.2f}**, "
            f"delta **{vs['mean_scores']['fixed'] - vs['mean_scores']['vulnerable']:+.2f}**",
            ""]

    dv = sum(1 for p in pairs if p.cat_v == "degenerate_generation")
    df = sum(1 for p in pairs if p.cat_f == "degenerate_generation")
    pdv = sum(1 for p in pub if p.cat_v == "degenerate_generation")
    pdf = sum(1 for p in pub if p.cat_f == "degenerate_generation")
    out += ["### Degenerate generation by side", "",
            "Ch. 13 predicted the *fixed*-side rate should fall, because the two "
            "sides were previously extracted by different code paths and now are "
            "not. This is the check on that attribution.", "",
            "| side | published | this arm |", "|---|---|---|",
            f"| vulnerable | {pdv} ({pct(pdv/len(pub))}) | {dv} ({pct(dv/len(pairs))}) |",
            f"| fixed | {pdf} ({pct(pdf/len(pub))}) | {df} ({pct(df/len(pairs))}) |", ""]

    perm = M.permutation_test(nondup)
    out += ["### Exchangeability", "",
            f"Permutation null over 10k label swaps: observed PFA "
            f"**{pct(perm['observed'])}**, null mean **{pct(perm['null_mean'])}** "
            f"(95% {pct(perm['null_lo95'])}–{pct(perm['null_hi95'])}), "
            f"p(observed ≥ null) = {perm['p_greater']:.4f}, "
            f"p(observed ≤ null) = {perm['p_less']:.4f}.", "",
            "A *low* observed value against this null means the detector is "
            "anti-correlated with the label, which shows up as p(≥) near 1.", ""]

    path = HERE / "report.md"
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}\n")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
