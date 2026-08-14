"""Read the v2 corpus by eye.

The structural invariants live in `scripts/validate_corpus.py` and are asserted
there, for any corpus - this script only runs that gate and then renders sampled
pairs as unified diffs, so a human can confirm that a "recovered" case really is
the same function on both sides with the CVE fix visible between them.

    python3 experiments/2026-08-22_extraction-v2/spot_check.py
    python3 experiments/2026-08-22_extraction-v2/spot_check.py --show 6
"""
import argparse
import difflib
import json
import random
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from validate_corpus import validate  # noqa: E402

CASES_V2 = HERE / "cases_v2"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases-dir", default=str(CASES_V2))
    ap.add_argument("--show", type=int, default=0, help="render N sample diffs")
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()

    n, passes, failures, kinds = validate(args.cases_dir)
    print(f"{n} usable cases; {len(failures)} structural failures")
    if failures:
        for cid, check, detail in failures[:10]:
            print(f"  {cid}: {check}: {detail}")
        print("\nCORPUS INVALID - run scripts/validate_corpus.py for the full report")
        return 1
    print("all structural checks passed "
          "(scripts/validate_corpus.py is the authority)")

    if not args.show:
        return 0

    published = {}
    for f in (ROOT / "cases").glob("*.json"):
        d = json.loads(f.read_text(encoding="utf-8"))
        published[d["case_id"]] = d["extraction_status"]

    cases = [json.loads(f.read_text(encoding="utf-8"))
             for f in sorted(Path(args.cases_dir).glob("*.json"))]
    cases = [c for c in cases if c["extraction_status"] == "ok"]

    # Weight the sample to the two recovered classes, so what is rendered is
    # the evidence the fix works rather than cases that already passed.
    rnd = random.Random(args.seed)
    by_origin = {}
    for c in cases:
        by_origin.setdefault(published.get(c["case_id"], "absent"), []).append(c)

    picks = []
    for origin in ("suspect_identifier_mismatch", "unsupported_multi_function_scope"):
        pool = by_origin.get(origin, [])
        picks += [(origin, c) for c in rnd.sample(pool, min(args.show // 2, len(pool)))]

    print(f"\nrecovered-from distribution: "
          f"{dict(Counter(o for o in by_origin for _ in by_origin[o]))}")

    for origin, c in picks:
        print("\n" + "=" * 72)
        print(f"{c['case_id']}   func={c['func_name']}   {c['repo']}  {c['cve_id']}")
        print(f"recovered from: {origin}")
        print(f"vulnerable lines {c['vulnerable_line_range']}  "
              f"fixed lines {c['fixed_line_range']}")
        print("=" * 72)
        body = list(difflib.unified_diff(
            c["vulnerable_snippet"].splitlines(),
            c["fixed_snippet"].splitlines(),
            fromfile="vulnerable", tofile="fixed", lineterm="", n=2))
        print("\n".join(body[:40]))
        if len(body) > 40:
            print(f"... ({len(body)-40} more diff lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
