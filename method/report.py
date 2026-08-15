"""Every number the method reports, computed from one results directory.

Reads only `method/results/<run>/` and `cases/`. The statistics themselves come
from `paired_eval.py` - this file decides what to measure, not how.

Two things about the metric are worth stating before reading any row.

Accuracy is defined over PAIRS, not functions. Each case gives two versions of
the same function, pre-patch and post-patch; the detector scores each one
independently and we ask only whether the vulnerable version scored higher.
That makes chance exactly 50%, with no class-imbalance correction to argue
about, because every case has exactly one of each by construction.

Ties are coverage, never a result. When the two versions receive the same
exposure the detector has not distinguished them, and that case is excluded
from the numerator AND the denominator. Scoring ties either way would let us
choose the headline. Accuracy here is therefore conditional on answering, and
every table reports the coverage it is conditional on.

Confidence intervals resample whole CVEs rather than cases: one CVE commit
often patches several functions and those cases fail together, so they are not
independent observations. The p-value is an exact two-sided binomial test
against 50%.

Usage:
    python3 method/report.py                       # -> stdout + method/report.md
    python3 method/report.py --run consensus_k5    # a different results dir
"""
import argparse
import collections
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts"))

import paired_eval as E  # noqa: E402
from data import load_cases, load_records  # noqa: E402
from corpus_sha import corpus_sha  # noqa: E402

TARGET = lambda j: j["target_exposure"]                             # noqa: E731
NET = lambda j: j["target_exposure"] - j["consensus_exposure"]      # noqa: E731


def fmt(s):
    """One summarise() dict as a markdown table row body."""
    ci = f"[{s['ci'][0]:.1%}, {s['ci'][1]:.1%}]" if s["ci"] else "-"
    p = f"{s['p_value']:.2g}" if s["p_value"] is not None else "-"
    acc = f"{s['accuracy']:.1%}" if s["accuracy"] is not None else "-"
    return (f"{s['n']} | {s['n_decided']} | {s['coverage']:.1%} | "
            f"**{acc}** | {ci} | {p}")


def headline(out, recs, nondup):
    """The pre-registered primary, and the full set as descriptive.

    The 87 `duplicate_of` cases are the same function reached through more than
    one CVE record. The analysis plan named the non-duplicate subset as primary
    in advance; the full set is reported beside it so the choice is visible
    rather than convenient.
    """
    out("## Headline\n")
    out("| set | cases | decided | coverage | accuracy | 95% CI | p vs 50% |")
    out("|---|---:|---:|---:|---:|---|---:|")
    prim = [r for r in recs if r["case_id"] in nondup]
    out(f"| **non-duplicate (primary)** | {fmt(E.summarise(prim, TARGET))} |")
    out(f"| all cases (descriptive) | {fmt(E.summarise(recs, TARGET))} |")
    s = E.summarise(prim, TARGET)
    out(f"\nOf the {s['n_decided']} pairs the method was willing to rank, it put "
        f"the vulnerable version on top {s['n_correct']} times. "
        f"ROC-AUC {s['auc']:.3f}.\n")


def operating_points(out, recs):
    """Target exposure vs net exposure, and the margin curve.

    Net exposure differences the target's own score against the reverse
    comparison the rubric also records. That removes the offset common to both
    judge calls - a weak reconstruction makes everything compared against it
    look defensively better - and decides substantially more cases at a lower
    accuracy, which is a genuine coverage/accuracy frontier rather than one
    fixed point.
    """
    out("## Operating points\n")
    out("| decision rule | cases | decided | coverage | accuracy | 95% CI | p vs 50% |")
    out("|---|---:|---:|---:|---:|---|---:|")
    out(f"| target exposure | {fmt(E.summarise(recs, TARGET))} |")
    out(f"| net (target - consensus) | {fmt(E.summarise(recs, NET))} |")

    out("\n### Margin threshold\n")
    out("| minimum margin | decided | coverage | accuracy |")
    out("|---:|---:|---:|---:|")
    for row in E.coverage_curve(recs, TARGET, margins=(1, 2, 3, 4)):
        acc = f"{row['accuracy']:.1%}" if row["accuracy"] is not None else "-"
        out(f"| >={row['margin']} | {row['n_decided']} | {row['coverage']:.1%} | {acc} |")
    out("\nDemanding a larger margin buys nothing, because the score quantises "
        "(below) and the margin carries almost no information beyond its sign.\n")


def score_distribution(out, recs):
    """Where the coverage goes.

    The rubric asks for 0-10 but binds ranges to severity classes, and the
    judge answers at the class rather than within it. Two versions of the same
    function usually land in the same class, and when they do the scores are
    identical and the case ties. That is the mechanism behind the tie rate -
    it is a property of the rubric, not of the idea.
    """
    out("## Exposure score distribution\n")
    vs = collections.Counter(r["judge_vs_vulnerable"]["target_exposure"] for r in recs)
    fs = collections.Counter(r["judge_vs_fixed"]["target_exposure"] for r in recs)
    keys = sorted(set(vs) | set(fs))
    out("| exposure | " + " | ".join(str(k) for k in keys) + " |")
    out("|---|" + "---:|" * len(keys))
    out("| vulnerable | " + " | ".join(str(vs[k]) for k in keys) + " |")
    out("| patched | " + " | ".join(str(fs[k]) for k in keys) + " |")

    total = sum(vs.values()) + sum(fs.values())
    modal = sum(vs[k] + fs[k] for k in (0, 4, 6) if k in keys)
    ties = [r for r in recs if r["judge_vs_vulnerable"]["target_exposure"]
            == r["judge_vs_fixed"]["target_exposure"]]
    both0 = [r for r in ties if r["judge_vs_vulnerable"]["target_exposure"] == 0]
    mv = sum(vs[k] * k for k in vs) / max(sum(vs.values()), 1)
    mf = sum(fs[k] * k for k in fs) / max(sum(fs.values()), 1)
    out(f"\n{modal/max(total,1):.0%} of all scores are exactly 0, 4 or 6. "
        f"Ties: {len(ties)} ({len(ties)/max(len(recs),1):.1%}), of which "
        f"{len(both0)} ({len(both0)/max(len(ties),1):.1%}) are the both-clean case.")
    out(f"\nMean exposure: vulnerable {mv:.2f}, patched {mf:.2f} - the direction "
        f"is right in the aggregate as well as in the ranking.\n")


def length_control(out, recs, cases):
    """The control that matters most on a fix-pair corpus.

    Security patches usually add lines, so "the shorter version is the
    vulnerable one" is a rule needing no intelligence at all, and on this corpus
    it is powerful. If the method were secretly ranking by length it would
    collapse on the equal-length stratum, where the shortcut is unavailable.
    """
    out("## Length stratification\n")
    def stratum(r):
        c = cases.get(r["case_id"])
        if not c:
            return None
        v = len(c["vulnerable_snippet"].splitlines())
        f = len(c["fixed_snippet"].splitlines())
        return "equal" if v == f else ("vuln_shorter" if v < f else "vuln_longer")

    comp = collections.Counter(filter(None, (stratum(r) for r in recs)))
    out(f"Corpus composition: {comp['vuln_shorter']} vulnerable-shorter, "
        f"{comp['equal']} equal, {comp['vuln_longer']} vulnerable-longer.\n")
    out("| stratum | cases | decided | coverage | accuracy | 95% CI | p vs 50% |")
    out("|---|---:|---:|---:|---:|---|---:|")
    for name in ("vuln_shorter", "equal", "vuln_longer"):
        sub = [r for r in recs if stratum(r) == name]
        if sub:
            out(f"| {name} | {fmt(E.summarise(sub, TARGET))} |")

    # How often the method picks the shorter side when the two differ. A
    # length-blind detector at accuracy a picks it at roughly a*P(shorter is
    # vulnerable) + (1-a)*P(longer is); a length-driven one approaches 100%.
    short = dec = 0
    for r in recs:
        c = cases.get(r["case_id"])
        if not c or stratum(r) == "equal":
            continue
        a = r["judge_vs_vulnerable"]["target_exposure"]
        b = r["judge_vs_fixed"]["target_exposure"]
        if a == b:
            continue
        dec += 1
        nv = len(c["vulnerable_snippet"].splitlines())
        nf = len(c["fixed_snippet"].splitlines())
        picked_vuln_side = a > b
        short += (nv < nf) if picked_vuln_side else (nf < nv)
    if dec:
        out(f"\nThe method chooses the shorter side on {short}/{dec} = "
            f"{short/dec:.1%} of unequal decided pairs.\n")


def leakage_control(out, recs):
    """Cases whose docstring may describe the fix, removed."""
    out("## Docstring-leakage control\n")
    flagged = [r for r in recs if r.get("heuristic_leakage_flag")]
    clean = [r for r in recs if not r.get("heuristic_leakage_flag")]
    out(f"{len(flagged)} of {len(recs)} cases carry the heuristic leakage flag.\n")
    out("| set | cases | decided | coverage | accuracy | 95% CI | p vs 50% |")
    out("|---|---:|---:|---:|---:|---|---:|")
    out(f"| unflagged only | {fmt(E.summarise(clean, TARGET))} |")
    out(f"| all cases | {fmt(E.summarise(recs, TARGET))} |")
    out("")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default="consensus_k5",
                    help="results directory under method/results/")
    ap.add_argument("--results-dir", default=None,
                    help="explicit results directory, overriding --run")
    ap.add_argument("--cases-dir", default=None)
    ap.add_argument("--out", default=None, help="markdown output (default method/report.md)")
    args = ap.parse_args()

    results_dir = Path(args.results_dir) if args.results_dir else HERE / "results" / args.run
    if not results_dir.is_dir():
        print(f"no results at {results_dir}\n"
              f"Run: python3 method/run.py --stage generate --k 5 && "
              f"python3 method/run.py --stage judge", file=sys.stderr)
        return 1

    cases = load_cases(args.cases_dir)
    recs = list(load_records(results_dir).values())
    if not recs:
        print(f"no result records in {results_dir}", file=sys.stderr)
        return 1
    nondup = {cid for cid, c in cases.items() if not c.get("duplicate_of")}
    sha, n_ok = corpus_sha(args.cases_dir)

    lines = []
    def out(s=""):
        lines.append(s)
        print(s)

    out(f"# Method report - `{results_dir.name}`\n")
    r0 = recs[0]["runtime"]
    out(f"- corpus: {n_ok} usable cases, `corpus_sha` `{sha}`")
    out(f"- model: `{r0['served_model']}`, seed {r0['seed']}, "
        f"judge temperature {r0['judge_temperature']}")
    out(f"- judge rubric `prompt_sha` `{r0['judge_prompt_sha']}`, "
        f"generator `{r0['generator_prompt_sha']}`")
    out(f"- K = {recs[0]['k']} reconstructions per case, {len(recs)} cases judged\n")

    headline(out, recs, nondup)
    operating_points(out, recs)
    score_distribution(out, recs)
    length_control(out, recs, cases)
    leakage_control(out, recs)

    path = Path(args.out) if args.out else HERE / "report.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
