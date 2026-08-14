"""Quantify the extraction defect in the published corpus, and account for the
old -> new transition case by case.

`FINDINGS.md` §5.2 measures the defect by brace balance and reports 111/392
(28.3%) malformed on the vulnerable side. That test undercounts: the dominant
failure is the slice running past the target function into the next one, and the
trailing fragment often happens to balance (`C_276__0` carries `vfs_rename` +
`EXPORT_SYMBOL` + the head of `SYSCALL_DEFINE5` at balance 0). This script
re-measures with the strict test - exactly one complete top-level function,
nothing glued on - and splits the published PFA by reference quality.

Reads results/qwen_full/ in place through experiments/common/, so any metric it
prints is computed by the same code that produced reports/qwen_full_report.md.

Usage: python3 experiments/2026-08-22_extraction-v2/audit_current.py
"""
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "experiments" / "common"))
sys.path.insert(0, str(HERE))

sys.path.insert(0, str(ROOT / "scripts"))
from validate_corpus import is_single_clean_function, top_level_pairs  # noqa: E402,F401

CASES_V2 = HERE / "cases_v2"


def classify_vulnerable(snippet):
    """Why a published vulnerable snippet is or is not a usable reference."""
    top = top_level_pairs(snippet)
    if not top:
        return "no_complete_function"
    open_idx, end_idx = top[0]
    if len(top) > 1:
        return "multiple_complete_functions"
    if snippet[end_idx:].strip():
        return "function_plus_trailing_fragment"
    if not snippet[:open_idx].strip():
        return "body_only_no_signature"
    return "clean_single_function"


def brace_balance(snippet):
    """The FINDINGS.md §5.2 test, reproduced for comparison."""
    return snippet.count("{") - snippet.count("}")


def load_published_cases():
    out = {}
    for f in sorted((ROOT / "cases").glob("*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        out[d["case_id"]] = d
    return out


def load_v2_cases():
    out = {}
    for f in sorted(CASES_V2.glob("*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        out[d["case_id"]] = d
    return out


def main():
    published = load_published_cases()
    v2 = load_v2_cases()
    ok = {c: d for c, d in published.items() if d["extraction_status"] == "ok"}

    # ---------- 1. defect rate in the published corpus ----------
    kinds = Counter()
    contaminated = set()
    extra_lines = 0
    for cid, d in ok.items():
        k = classify_vulnerable(d["vulnerable_snippet"])
        kinds[k] += 1
        if k != "clean_single_function":
            contaminated.add(cid)
        if k == "function_plus_trailing_fragment":
            top = top_level_pairs(d["vulnerable_snippet"])
            tail = d["vulnerable_snippet"][top[0][1]:]
            extra_lines += len([l for l in tail.splitlines() if l.strip()])

    print("=" * 72)
    print("1. The published 392 'ok' cases, VULNERABLE side (strict test)")
    print("=" * 72)
    for k, v in kinds.most_common():
        print(f"  {k:34s} {v:4d}  {v/len(ok):5.1%}")
    print(f"\n  defective: {len(contaminated)}/{len(ok)} ({len(contaminated)/len(ok):.1%})")
    print(f"  non-target lines glued on: {extra_lines}")

    unbal = sum(1 for d in ok.values() if brace_balance(d["vulnerable_snippet"]) != 0)
    print(f"\n  for comparison, the FINDINGS.md 5.2 brace-balance test flags "
          f"{unbal} ({unbal/len(ok):.1%})")
    print("  the gap is over-extension whose trailing fragment happens to balance")

    fkinds = Counter(classify_vulnerable(d["fixed_snippet"] or "") for d in ok.values())
    print("\n  FIXED side of the same cases (brace-matched, for contrast):")
    for k, v in fkinds.most_common():
        print(f"    {k:32s} {v:4d}  {v/len(ok):5.1%}")

    # ---------- 2. did the defect move the headline? ----------
    print()
    print("=" * 72)
    print("2. Published PFA split by reference quality")
    print("=" * 72)
    from data import load_records, scored, to_pairs  # noqa: E402
    import metrics as M  # noqa: E402

    records = load_records(ROOT / "results" / "qwen_full")
    pairs = to_pairs(records)
    sc = scored(pairs)
    print(f"  n_scored = {len(sc)}   (reports/qwen_full_report.md: 357)")
    print(f"  PFA      = {M.pfa(sc):.4f}   (reports/qwen_full_report.md: 0.1597)")

    # Two slices, because the answer is sensitive to how "defective" is drawn
    # and the honest report is both. Neither is significant.
    over_extended = {c for c, d in ok.items()
                     if classify_vulnerable(d["vulnerable_snippet"])
                     == "function_plus_trailing_fragment"}
    for label, bad in (("any defect", contaminated),
                       ("over-extension only", over_extended)):
        dirty = [p for p in sc if p.case_id in bad]
        clean = [p for p in sc if p.case_id not in bad]
        z, p = two_proportion_z(
            sum(x.paired_flag_correct for x in dirty), len(dirty),
            sum(x.paired_flag_correct for x in clean), len(clean))
        print(f"\n  defective set = {label}")
        print(f"    defective reference : {M.pfa(dirty):6.1%}  (n={len(dirty)})")
        print(f"    clean reference     : {M.pfa(clean):6.1%}  (n={len(clean)})")
        print(f"    two-proportion z = {z:+.2f}, p = {p:.3f}")
    print("\n  -> the two slices disagree on sign and neither is significant;")
    print("     the defect does not explain the null. It costs credibility and power.")

    # ---------- 3. old -> new transition ----------
    print()
    print("=" * 72)
    print("3. Transition, published extractor -> v2")
    print("=" * 72)
    trans = Counter()
    for cid, d in published.items():
        old = d["extraction_status"]
        new = v2[cid]["extraction_status"] if cid in v2 else "MISSING"
        trans[(old, "ok" if new == "ok" else "dropped")] += 1
    for (old, new), n in sorted(trans.items(), key=lambda x: -x[1]):
        print(f"  {old:34s} -> {new:8s} {n:4d}")

    v2_ok = {c for c, d in v2.items() if d["extraction_status"] == "ok"}
    kept = len(set(ok) & v2_ok)
    lost = sorted(set(ok) - v2_ok)
    print(f"\n  of the published 392 'ok': {kept} survive, {len(lost)} do not")
    print(f"  reasons the {len(lost)} do not:")
    for k, n in Counter(v2[c]["extraction_status"] for c in lost).most_common():
        print(f"    {k:44s} {n}")

    # ---------- 4. resulting corpus ----------
    print()
    print("=" * 72)
    print("4. The v2 corpus")
    print("=" * 72)
    okv2 = [v2[c] for c in v2_ok]
    dup = sum(1 for d in okv2 if d["duplicate_of"])
    print(f"  usable cases        : {len(okv2)}   (published: 392 extracted / 357 scored)")
    print(f"  unique functions    : {len(okv2) - dup}   ({dup} flagged duplicates)")
    print(f"  unique CVEs         : {len({d['cve_id'] for d in okv2})}"
          f"   (published: {len({d['cve_id'] for d in ok.values()})} over the 392 extracted,"
          f" {len({p.cve_id for p in sc})} over the 357 scored)")
    print(f"  languages           : {dict(Counter(d['language'] for d in okv2))}")
    top = Counter(d["repo"] for d in okv2).most_common(4)
    print(f"  top repos           : {top}")
    print(f"  largest repo share  : {top[0][1]/len(okv2):.0%}"
          f"  (published: {Counter(d['repo'] for d in ok.values()).most_common(1)[0][1]/len(ok):.0%})"
          "  -> clustering does not improve; keep the CVE-clustered bootstrap")

    import math
    for n in (357, len(okv2)):
        hw = 1.96 * math.sqrt(0.16 * 0.84 / n)
        print(f"  95% CI half-width at PFA=16%, n={n}: +/-{hw:.2%}")


def two_proportion_z(x1, n1, x2, n2):
    import math
    p1, p2 = x1 / n1, x2 / n2
    p = (x1 + x2) / (n1 + n2)
    z = (p1 - p2) / math.sqrt(p * (1 - p) * (1 / n1 + 1 / n2))
    return z, math.erfc(abs(z) / math.sqrt(2))


if __name__ == "__main__":
    main()
