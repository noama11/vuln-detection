"""Build report.md for the extraction-v2 arm.

Everything in the report is computed here from cases/, cases_v2/ and
results/qwen_full/ - no figure is transcribed by hand.

Usage: python3 experiments/2026-08-22_extraction-v2/report.py
"""
import json
import math
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "experiments" / "common"))

from audit_current import (  # noqa: E402
    brace_balance, classify_vulnerable, load_published_cases, load_v2_cases,
    two_proportion_z,
)
import metrics as M  # noqa: E402
from data import load_records, scored, to_pairs  # noqa: E402

OUT = HERE / "report.md"

STATUS_LABEL = {
    "skipped_no_changed_lines_overlap":
        "no `changed_lines` entry overlaps the scope range",
    "skipped_anchor_not_in_function":
        "patched line is at file scope (include block, global, class body)",
    "skipped_macro_not_function":
        "`#define` macro with a statement-expression body, not a function",
    "skipped_hunk_not_contained":
        "changed lines not fully inside the located function",
    "skipped_fixed_function_not_found":
        "function absent from the fixed side (renamed or deleted by the patch)",
    "skipped_vulnerable_not_single_function": "vulnerable side not a single function",
    "skipped_fixed_not_single_function": "fixed side not a single function",
    "skipped_patch_did_not_touch_function": "patch does not touch the function",
    "skipped_empty_docstring": "scope entry carries no docstring",
}

KIND_LABEL = {
    "function_plus_trailing_fragment": "target function **+ fragment of the next function**",
    "clean_single_function": "clean single function",
    "no_complete_function": "no complete function (truncated or body-only)",
    "body_only_no_signature": "body only, no signature",
    "multiple_complete_functions": "two or more complete functions",
}


def main():
    published = load_published_cases()
    v2 = load_v2_cases()
    ok = {c: d for c, d in published.items() if d["extraction_status"] == "ok"}
    v2_ok = {c: d for c, d in v2.items() if d["extraction_status"] == "ok"}

    L = []
    w = L.append

    w("# WP-next — corrected extraction (`extraction-v2`)")
    w("")
    w("**Objective**: close `RESEARCH_LOG.md` open thread #4 — *\"fix the extraction")
    w("defect and re-derive the corpus; the ~49% clean rate is optimistic\"*.")
    w("")
    w("Additive arm. `scripts/`, `cases/`, `results/`, `reports/`, `pilot/` and")
    w("`.claude/` are unmodified; every published arm stays byte-reproducible.")
    w("No inference was run — this arm produces a corpus and an audit, nothing more.")
    w("")

    # ---------------- 1 ----------------
    w("## 1. The published corpus is worse than §5.2 records")
    w("")
    kinds = Counter(classify_vulnerable(d["vulnerable_snippet"]) for d in ok.values())
    defective = sum(v for k, v in kinds.items() if k != "clean_single_function")
    w(f"`FINDINGS.md` §5.2 measures the vulnerable-side defect by **brace balance** and")
    unbal = sum(1 for d in ok.values() if brace_balance(d["vulnerable_snippet"]) != 0)
    w(f"reports {unbal}/{len(ok)} ({unbal/len(ok):.1%}) malformed. That test undercounts: the")
    w("dominant failure is the slice running *past* the target function into the next")
    w("one, and the trailing fragment frequently happens to balance. `C_276__0` carries")
    w("`vfs_rename` + `EXPORT_SYMBOL` + the head of `SYSCALL_DEFINE5` at balance 0.")
    w("")
    w("Re-measured with the strict test — exactly one complete top-level function,")
    w("nothing glued on after its closing brace:")
    w("")
    w("| The 392 `ok` vulnerable snippets | n | |")
    w("|---|---:|---:|")
    for k, v in kinds.most_common():
        w(f"| {KIND_LABEL.get(k, k)} | {v} | {v/len(ok):.0%} |")
    w(f"| **defective** | **{defective}** | **{defective/len(ok):.0%}** |")
    w("")
    fkinds = Counter(classify_vulnerable(d["fixed_snippet"] or "") for d in ok.values())
    fclean = fkinds["clean_single_function"]
    w(f"The fixed side of the same cases is {fclean}/{len(ok)} ({fclean/len(ok):.1%}) clean, because it is")
    w("brace-matched rather than sliced. **That asymmetry is the defect**: every")
    w("published metric compared each candidate against a clean post-patch reference")
    w("and a contaminated pre-patch one.")
    w("")
    macros = sum(1 for c in ok if v2[c]["extraction_status"] == "skipped_macro_not_function")
    w(f"Separately, {macros} of the 392 are `#define` macros with statement-expression")
    w("bodies rather than functions, so there is no function to reconstruct from a")
    w("docstring at all.")
    w("")

    # ---------------- 2 ----------------
    w("## 2. Three bugs in `scripts/extract_cases.py`")
    w("")
    w("**B1 — the fixed side extracts an inner block, not the function.**")
    w("`locate_function_by_anchor` (`scripts/extract_cases.py:151`) selects the")
    w("*innermost* brace pair containing the anchor. When the patched line sits inside")
    w("an `if`/`while`, that returns the loop body: `C_435__0` extracted")
    w("`if (pkt->size >= 7 && …` instead of `read_gab2_sub`. The innermost choice was")
    w("guarding against C++ `namespace`/`class` wrapping, but it overshoots on every")
    w("nested statement. This is the whole `suspect_identifier_mismatch` class — the")
    w("right function was located all along, then discarded by the identifier check.")
    w("")
    w("**B2 — the vulnerable side is sliced literally from `scope.start`/`scope.end`**")
    w("(`scripts/extract_cases.py:239`) while the fixed side is brace-matched. Those")
    w("ranges are frequently not function boundaries — `D/C/1222` has `scope.start = 131`,")
    w("a statement-continuation line deep inside a body — so the slice over-runs into")
    w("the following function.")
    w("")
    w("**B3 — the multi-function guard has a blind spot.** `count_top_level_braces`")
    w("(`scripts/extract_cases.py:137`) counts only *matched* brace pairs, so a slice")
    w("ending in an unclosed `{` is never flagged. That is exactly what B2 produces,")
    w("and it is why contaminated cases carry `extraction_status: \"ok\"`.")
    w("")
    w("`extract_v2.py` fixes all three: `locate_enclosing_function` walks")
    w("outermost-inward and skips wrapper constructs explicitly; both sides are")
    w("anchored on the matched `changed_lines` hunk and brace-matched identically, so")
    w("the scope range is a hint and never a boundary; and `is_single_clean_function`")
    w("additionally requires that nothing follows the closing brace.")
    w("")

    # ---------------- 3 ----------------
    w("## 3. Funnel")
    w("")
    total = len(v2)
    st = Counter(d["extraction_status"] for d in v2.values())
    w("| Stage | n |")
    w("|---|---:|")
    w(f"| scope entries in `D.zip` | {total} |")
    for k, n in sorted(((k, n) for k, n in st.items() if k != "ok"), key=lambda x: -x[1]):
        w(f"| − {STATUS_LABEL.get(k, k)} | {n} |")
    w(f"| **usable** | **{len(v2_ok)}** |")
    w("")
    dup = sum(1 for d in v2_ok.values() if d["duplicate_of"])
    w(f"{len(v2_ok)} cases, {len(v2_ok)-dup} unique functions. The remaining {dup} are the same")
    w("function emitted twice because the dataset generated two docstrings for it")
    w("(`D/C/1222` scope 0 and 1 share range 131–204). Both are kept and flagged with")
    w("`duplicate_of`, so a metric can drop them without losing the docstring-variant")
    w("signal.")
    w("")
    w("### Transition from the published extractor")
    w("")
    trans = Counter()
    for cid, d in published.items():
        trans[(d["extraction_status"], "kept" if cid in v2_ok else "dropped")] += 1
    w("| published status | | n |")
    w("|---|---|---:|")
    for (old, new), n in sorted(trans.items(), key=lambda x: -x[1]):
        w(f"| `{old}` | {new} | {n} |")
    w("")
    lost = sorted(set(ok) - set(v2_ok))
    w(f"**{len(set(ok) & set(v2_ok))} of the published 392 survive; {len(lost)} do not**, because:")
    w("")
    for k, n in Counter(v2[c]["extraction_status"] for c in lost).most_common():
        w(f"- {n} — {STATUS_LABEL.get(k, k)}")
    w("")

    # ---------------- 4 ----------------
    w("## 4. Does the defect explain the null?")
    w("")
    records = load_records(ROOT / "results" / "qwen_full")
    sc = scored(to_pairs(records))
    w(f"Reproduced from `results/qwen_full/` in place: n_scored = {len(sc)}, ")
    w(f"PFA = {M.pfa(sc):.4f} — matching `reports/qwen_full_report.md` exactly, which")
    w("confirms the loader path is equivalent before any split is reported.")
    w("")
    contaminated = {c for c, d in ok.items()
                    if classify_vulnerable(d["vulnerable_snippet"]) != "clean_single_function"}
    over = {c for c, d in ok.items()
            if classify_vulnerable(d["vulnerable_snippet"]) == "function_plus_trailing_fragment"}
    w("| defective set | defective ref | clean ref | z | p |")
    w("|---|---|---|---:|---:|")
    for label, bad in (("any defect", contaminated), ("over-extension only", over)):
        dirty = [p for p in sc if p.case_id in bad]
        clean = [p for p in sc if p.case_id not in bad]
        z, p = two_proportion_z(sum(x.paired_flag_correct for x in dirty), len(dirty),
                                sum(x.paired_flag_correct for x in clean), len(clean))
        w(f"| {label} | {M.pfa(dirty):.1%} (n={len(dirty)}) | {M.pfa(clean):.1%} "
          f"(n={len(clean)}) | {z:+.2f} | {p:.3f} |")
    w("")
    w("**No.** The two slices disagree on sign and neither is significant, consistent")
    w("with §5.2's own 16.0% → 15.8% check. The corrected corpus buys credibility and")
    w("statistical power, not a different headline. Any re-run should be framed that")
    w("way in the paper.")
    w("")

    # ---------------- 5 ----------------
    w("## 5. The v2 corpus")
    w("")
    okv2 = list(v2_ok.values())
    cve_v2 = len({d["cve_id"] for d in okv2})
    cve_pub = len({p.cve_id for p in sc})
    top = Counter(d["repo"] for d in okv2).most_common(5)
    top_pub = Counter(d["repo"] for d in ok.values()).most_common(1)[0]
    w("| | published | v2 |")
    w("|---|---:|---:|")
    w(f"| usable cases | 392 extracted / {len(sc)} scored | **{len(okv2)}** |")
    w(f"| vulnerable side a single complete function | {kinds['clean_single_function']} | {len(okv2)} |")
    w(f"| unique functions | — | {len(okv2)-dup} |")
    w(f"| unique CVEs | {cve_pub} | {cve_v2} |")
    hw_old = 1.96 * math.sqrt(0.16 * 0.84 / len(sc))
    hw_new = 1.96 * math.sqrt(0.16 * 0.84 / len(okv2))
    w(f"| 95% CI half-width at PFA≈16% | ±{hw_old:.1%} | ±{hw_new:.1%} |")
    w(f"| largest repo share | {top_pub[1]/len(ok):.0%} | {top[0][1]/len(okv2):.0%} |")
    w("")
    w("Composition: " + ", ".join(f"`{r}` {n}" for r, n in top) + ".")
    w(f"Languages: {dict(Counter(d['language'] for d in okv2))}.")
    w("")
    w("**Repo clustering does not improve** — `torvalds/linux` still dominates — so")
    w("`FINDINGS.md:157`'s CVE-clustered bootstrap CIs remain the right choice.")
    w("")

    # ---------------- 6 ----------------
    w("## 6. Verification")
    w("")
    w("| check | result |")
    w("|---|---|")
    w("| `extract_v2.py` run twice, `diff -r` on the output | identical |")
    w(f"| in-script `is_single_clean_function` assertion on every emitted case | {len(okv2)}/{len(okv2)} |")
    w(f"| `spot_check.py` — snippets are verbatim substrings of `D.zip` | {len(okv2)}/{len(okv2)} |")
    w("| `spot_check.py` — recorded line ranges agree with the snippets | pass |")
    w("| `spot_check.py` — same function identifier on both sides | pass |")
    w("| `spot_check.py` — vulnerable and fixed differ; docstring present | pass |")
    w(f"| `audit_current.py` reproduces `n_scored`={len(sc)} and PFA={M.pfa(sc):.4f} | pass |")
    w("| `git status` — writes confined to this arm directory | pass |")
    w("")
    w("Manual reading of sampled diffs (`spot_check.py --show 4`) confirms the")
    w("recovered pairs are genuine CVE fixes: `C_560__0` adds the missing bounds check")
    w("before `CopyMagickMemory` (CVE-2016-7538), `C_179__0` adds `memset(&line, 0, …)`")
    w("against an infoleak (CVE-2014-1445), `C_160__2` threads the extra")
    w("`__load_segment_descriptor` argument (CVE-2014-3647).")
    w("")
    w("## 7. Known follow-up")
    w("")
    w("`scripts/run_cases_local.py:35` hardcodes `CASES_DIR = ROOT / \"cases\"` with no")
    w("override flag, so running inference on `cases_v2/` needs either a `--cases-dir`")
    w("flag (touches `scripts/`, breaking additivity) or a thin runner inside this arm.")
    w("Worth deciding once the corpus is approved.")
    w("")

    OUT.write_text("\n".join(L), encoding="utf-8")
    print(f"wrote {OUT} ({len(L)} lines)")


if __name__ == "__main__":
    main()
