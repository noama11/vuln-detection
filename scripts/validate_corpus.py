"""Structural validation for a case corpus, independent of whatever built it.

An earlier extraction defect survived a long run of experiments because
`extraction_status: "ok"` was written by the same code that had the bug, and
the one validity check being run - brace balance - could not see the failure
mode (a slice that over-runs the target function but happens to balance).
Nothing verified the corpus against the raw data in D.zip.

This module is that check. It knows nothing about how a corpus was produced; it
asserts properties every usable case must have, and exits non-zero when they do
not hold. Run it on any corpus before trusting a number derived from it.

    python3 scripts/validate_corpus.py                          # cases/
    python3 scripts/validate_corpus.py --cases-dir <dir>        # any other corpus
    python3 scripts/validate_corpus.py --cases-dir <dir> --quiet

Exit code is 1 if any case fails, so it can be used as a gate.
"""
import argparse
import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from extract_cases import compute_brace_pairs  # noqa: E402

DEFAULT_CASES = ROOT / "cases"
ZIP_PATH = ROOT / "D.zip"

FUNC_NAME_RE = re.compile(r"(\w+)\s*\(")
NON_NAME_IDENTS = {
    "if", "for", "while", "switch", "return", "sizeof", "do", "else", "case",
    "defined", "typeof", "__attribute__", "static_assert", "COMPILE_ASSERT",
    "alignas", "decltype", "noexcept",
}

MIN_DOCSTRING_CHARS = 40


# --------------------------------------------------------------------------- #
# the structural predicates
# --------------------------------------------------------------------------- #

def top_level_pairs(snippet):
    """Brace pairs in `snippet` not nested inside any other pair in `snippet`."""
    pairs = compute_brace_pairs(snippet)
    return sorted(
        (s, e) for i, (s, e) in enumerate(pairs)
        if not any(j != i and pairs[j][0] < s and e < pairs[j][1]
                   for j in range(len(pairs)))
    )


def is_single_clean_function(snippet):
    """Exactly one complete top-level function, a signature before it, and
    nothing glued on after its closing brace.

    The third clause is the one that matters. `count_top_level_braces` in
    extract_cases.py counts only *matched* pairs, so a slice ending in an
    unclosed '{' - the target function plus a truncated fragment of the next one
    - passes it. Half the published corpus is exactly that.
    """
    top = top_level_pairs(snippet)
    if len(top) != 1:
        return False
    open_idx, end_idx = top[0]
    if snippet[end_idx:].strip():
        return False
    return bool(snippet[:open_idx].strip())


def classify(snippet):
    """Why a snippet is or is not a usable reference. The taxonomy the audit
    reports; `clean_single_function` is the only passing value."""
    if not snippet:
        return "empty"
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


def looks_like_macro(snippet):
    """A multi-line `#define m(x) ({ ... })` presents a brace pair with a
    `name(args)` header, so it is otherwise indistinguishable from a function.
    There is no function to reconstruct from a docstring, so it is not usable."""
    head = snippet[:snippet.find("{")] if "{" in snippet else snippet
    return any(l.lstrip().startswith("#") for l in head.splitlines())


def function_name(snippet):
    """First non-keyword identifier followed by '(' in the signature."""
    head = snippet[:snippet.find("{")] if "{" in snippet else snippet
    names = [n for n in FUNC_NAME_RE.findall(head) if n not in NON_NAME_IDENTS]
    return names[0] if names else None


# --------------------------------------------------------------------------- #
# the gate
# --------------------------------------------------------------------------- #

CHECKS = [
    "snippet is a verbatim substring of D.zip",
    "recorded line range agrees with the snippet",
    "exactly one complete function per side",
    "not a preprocessor macro",
    "same function identifier on both sides",
    "vulnerable and fixed differ",
    f"docstring present (>= {MIN_DOCSTRING_CHARS} chars)",
]


def validate(cases_dir, check_zip=True):
    """Returns (n_ok_cases, passes: Counter, failures: list, kinds: Counter)."""
    cases_dir = Path(cases_dir)
    cases = []
    for fp in sorted(cases_dir.glob("*.json")):
        c = json.loads(fp.read_text(encoding="utf-8"))
        if c.get("extraction_status") == "ok":
            cases.append(c)

    zf = zipfile.ZipFile(ZIP_PATH) if check_zip else None
    file_cache = {}
    passes = Counter()
    failures = []
    kinds = Counter()

    def fail(cid, check, detail):
        failures.append((cid, check, detail))

    for c in cases:
        cid = c["case_id"]
        ext = "cpp" if c.get("language") == "cpp" else "c"
        sides = {"vulnerable": c.get("vulnerable_snippet") or "",
                 "fixed": c.get("fixed_snippet") or ""}

        for side, snippet in sides.items():
            if side == "vulnerable":
                kinds[classify(snippet)] += 1

            # 1 + 2: the snippet is really in D.zip where the record says it is
            if zf is not None:
                path = f"{c['sample_id']}/{side}.{ext}"
                if path not in file_cache:
                    file_cache[path] = zf.read(path).decode("utf-8", "replace")
                text = file_cache[path]

                if snippet and snippet in text:
                    passes[CHECKS[0]] += 1
                else:
                    fail(cid, CHECKS[0], f"{side} snippet not found in {path}")

                rng = c.get(f"{side}_line_range")
                if rng and snippet:
                    lo, hi = rng
                    window = "\n".join(text.split("\n")[lo - 1:hi])
                    # Normalise the line terminator the two corpora disagree on:
                    # extract_cases.py joins lines with their '\n' retained, so
                    # its snippets carry a trailing newline; extract_v2.py slices
                    # to the closing brace and does not.
                    body = snippet.rstrip("\n")
                    # The snippet ends at the closing brace, so trailing text on
                    # that line (`} /* cypress_open */`) is outside it by
                    # design: the invariant is prefix, not equality.
                    n_file = text.count("\n") + 1
                    if window.startswith(body) and body.count("\n") == hi - lo:
                        passes[CHECKS[1]] += 1
                    elif hi > n_file:
                        # The dataset's scope range runs past the end of the
                        # file; slicing clamps silently, so the stored range
                        # describes more lines than the snippet contains.
                        fail(cid, CHECKS[1],
                             f"{side}_line_range {lo}-{hi} over-runs the file "
                             f"({n_file} lines); snippet has {body.count(chr(10))+1}")
                    else:
                        fail(cid, CHECKS[1],
                             f"{side}_line_range {lo}-{hi} claims {hi-lo+1} lines, "
                             f"snippet has {body.count(chr(10))+1}")
                else:
                    fail(cid, CHECKS[1], f"{side}_line_range missing")

            # 3: exactly one complete function
            clean = is_single_clean_function(snippet)
            if clean:
                passes[CHECKS[2]] += 1
            else:
                fail(cid, CHECKS[2], f"{side} is {classify(snippet)}")

            # 4: not a macro. Only meaningful once the head region is known to
            # be a signature - on a malformed slice it is arbitrary body text,
            # and any `#define` inside it would read as a false positive. Those
            # cases already fail check 3.
            if not clean:
                passes[CHECKS[3]] += 1
            elif not looks_like_macro(snippet):
                passes[CHECKS[3]] += 1
            else:
                fail(cid, CHECKS[3], f"{side} is a #define macro body")

        # 5: both sides are the same function
        name = c.get("func_name") or function_name(sides["vulnerable"])
        if name and all(re.search(r"\b" + re.escape(name) + r"\s*\(", s)
                        for s in sides.values()):
            passes[CHECKS[4]] += 1
        else:
            fail(cid, CHECKS[4],
                 f"identifier {name!r} not present on both sides" if name
                 else "no function name derivable from the vulnerable side")

        # 6: the patch is visible
        if sides["vulnerable"].strip() and sides["vulnerable"].strip() != sides["fixed"].strip():
            passes[CHECKS[5]] += 1
        else:
            fail(cid, CHECKS[5], "vulnerable and fixed are identical or empty")

        # 7: there is a spec to reconstruct from
        if len((c.get("docstring") or "").strip()) >= MIN_DOCSTRING_CHARS:
            passes[CHECKS[6]] += 1
        else:
            fail(cid, CHECKS[6], "docstring missing or trivially short")

    return len(cases), passes, failures, kinds


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cases-dir", default=str(DEFAULT_CASES))
    ap.add_argument("--no-zip", action="store_true",
                    help="skip the D.zip cross-checks (faster, weaker)")
    ap.add_argument("--quiet", action="store_true", help="summary only")
    ap.add_argument("--max-failures", type=int, default=15)
    args = ap.parse_args()

    cases_dir = Path(args.cases_dir)
    n, passes, failures, kinds = validate(cases_dir, check_zip=not args.no_zip)

    rel = cases_dir.relative_to(ROOT) if cases_dir.is_relative_to(ROOT) else cases_dir
    print(f"corpus: {rel}")
    print(f"cases with extraction_status == 'ok': {n}\n")

    # per-side checks run twice per case, per-pair checks once
    per_side = {CHECKS[0], CHECKS[1], CHECKS[2], CHECKS[3]}
    for check in CHECKS:
        if args.no_zip and check in (CHECKS[0], CHECKS[1]):
            continue
        denom = n * 2 if check in per_side else n
        got = passes[check]
        mark = "ok  " if got == denom else "FAIL"
        print(f"  [{mark}] {check:44s} {got}/{denom}")

    if not args.quiet:
        print("\n  vulnerable-side shape:")
        for k, v in kinds.most_common():
            print(f"    {k:34s} {v:4d}  {v/n:5.1%}" if n else "")

    if failures:
        by_check = Counter(f[1] for f in failures)
        print(f"\n{len(failures)} FAILURES across {len({f[0] for f in failures})} cases:")
        for check, cnt in by_check.most_common():
            print(f"  {cnt:4d}  {check}")
        if not args.quiet:
            print("\n  first failures:")
            for cid, check, detail in failures[:args.max_failures]:
                print(f"    {cid:14s} {check}: {detail}")
            if len(failures) > args.max_failures:
                print(f"    ... {len(failures) - args.max_failures} more")
        print("\nCORPUS INVALID")
        return 1

    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
