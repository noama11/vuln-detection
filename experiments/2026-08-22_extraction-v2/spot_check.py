"""Spot check for the v2 corpus - independent of the extractor's own logic.

The self-check inside extract_v2.py verifies the guard it applied. This verifies
the *claim*: that each emitted pair is the same function on both sides, that the
snippets are byte-for-byte substrings of the raw files in D.zip, and that the
patch is actually visible in the diff.

Runs the structural checks over all 635 usable cases, then prints unified diffs
for a sample so the pairs can be read by eye.

Usage:
  python3 experiments/2026-08-22_extraction-v2/spot_check.py            # checks only
  python3 experiments/2026-08-22_extraction-v2/spot_check.py --show 10  # + diffs
"""
import argparse
import difflib
import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
from extract_v2 import is_single_clean_function  # noqa: E402

CASES_V2 = HERE / "cases_v2"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", type=int, default=0, help="print N sample diffs")
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()

    zf = zipfile.ZipFile(ROOT / "D.zip")
    published = {}
    for f in (ROOT / "cases").glob("*.json"):
        d = json.loads(f.read_text(encoding="utf-8"))
        published[d["case_id"]] = d["extraction_status"]

    cases = []
    for f in sorted(CASES_V2.glob("*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        if d["extraction_status"] == "ok":
            cases.append(d)

    checks = Counter()
    failures = []
    file_cache = {}

    for c in cases:
        ext = "cpp" if c["language"] == "cpp" else "c"
        for side, key in (("vulnerable", "vulnerable_snippet"), ("fixed", "fixed_snippet")):
            path = f"{c['sample_id']}/{side}.{ext}"
            if path not in file_cache:
                file_cache[path] = zf.read(path).decode("utf-8", "replace")
            text = file_cache[path]
            snippet = c[key]

            # 1. the snippet is a verbatim slice of the raw file
            if snippet in text:
                checks[f"{side}: verbatim substring of D.zip"] += 1
            else:
                failures.append((c["case_id"], f"{side} snippet is not a substring of {path}"))

            # 2. the recorded line range points at that slice. The snippet ends
            # at the function's closing brace, so anything the source puts after
            # it on the same line - `} /* cypress_open */` is common in
            # libsndfile and cypress_m8 - is outside the snippet by design.
            # The invariant is therefore prefix, not equality.
            lo, hi = c[f"{side}_line_range"]
            lines = text.split("\n")
            window = "\n".join(lines[lo - 1:hi])
            if window.startswith(snippet) and snippet.count("\n") == hi - lo:
                checks[f"{side}: line range agrees"] += 1
            else:
                failures.append((c["case_id"], f"{side}_line_range {lo}-{hi} does not match snippet"))

            # 3. exactly one complete function
            if is_single_clean_function(snippet):
                checks[f"{side}: single complete function"] += 1
            else:
                failures.append((c["case_id"], f"{side} is not a single complete function"))

        # 4. both sides are the same function
        name = c["func_name"]
        if (re.search(r"\b" + re.escape(name) + r"\s*\(", c["vulnerable_snippet"])
                and re.search(r"\b" + re.escape(name) + r"\s*\(", c["fixed_snippet"])):
            checks["pair: same function identifier on both sides"] += 1
        else:
            failures.append((c["case_id"], f"identifier '{name}' missing from one side"))

        # 5. the patch is visible
        if c["vulnerable_snippet"].strip() != c["fixed_snippet"].strip():
            checks["pair: vulnerable and fixed differ"] += 1
        else:
            failures.append((c["case_id"], "vulnerable and fixed are identical"))

        # 6. the docstring is present and non-trivial
        if len((c["docstring"] or "").strip()) >= 40:
            checks["pair: docstring >= 40 chars"] += 1
        else:
            failures.append((c["case_id"], "docstring missing or trivially short"))

    n = len(cases)
    print(f"structural checks over all {n} usable cases\n")
    for k, v in sorted(checks.items()):
        mark = "ok  " if v == n else "FAIL"
        print(f"  [{mark}] {k:46s} {v}/{n}")
    if failures:
        print(f"\n{len(failures)} FAILURES:")
        for cid, why in failures[:20]:
            print(f"  {cid}: {why}")
        sys.exit(1)
    print("\nall structural checks passed")

    if not args.show:
        return

    # Sample diffs, weighted to the two recovered classes so the fix is visible.
    import random
    rnd = random.Random(args.seed)
    by_origin = {"suspect_identifier_mismatch": [], "unsupported_multi_function_scope": [],
                 "ok": [], "skipped": []}
    for c in cases:
        by_origin.setdefault(published.get(c["case_id"], "?"), []).append(c)

    picks = []
    for origin in ("suspect_identifier_mismatch", "unsupported_multi_function_scope"):
        pool = by_origin.get(origin, [])
        picks += [(origin, c) for c in rnd.sample(pool, min(args.show // 2, len(pool)))]

    for origin, c in picks:
        print("\n" + "=" * 72)
        print(f"{c['case_id']}   func={c['func_name']}   {c['repo']}  {c['cve_id']}")
        print(f"recovered from: {origin}")
        print(f"vulnerable lines {c['vulnerable_line_range']}  fixed lines {c['fixed_line_range']}")
        print("=" * 72)
        diff = difflib.unified_diff(
            c["vulnerable_snippet"].splitlines(),
            c["fixed_snippet"].splitlines(),
            fromfile="vulnerable", tofile="fixed", lineterm="", n=2)
        body = [l for l in diff]
        print("\n".join(body[:40]))
        if len(body) > 40:
            print(f"... ({len(body)-40} more diff lines)")


if __name__ == "__main__":
    main()
