"""Corrected case extraction. Writes experiments/2026-08-22_extraction-v2/cases_v2/.

Read-only w.r.t. D.zip, cases/, results/, reports/ and scripts/ - this arm is
additive like every other one, so the published corpus stays byte-reproducible.

`scripts/extract_cases.py` drops 400 of 792 scope entries and mis-extracts about
half of the 392 it keeps. Three separate defects, each fixed here:

B1  `locate_function_by_anchor` picks the *innermost* brace pair containing the
    anchor. When the patched line sits inside an if/while, that returns the loop
    body rather than the function - `C_435__0` extracted `if (pkt->size >= 7 &&`
    instead of `read_gab2_sub`. The innermost choice was guarding against C++
    namespace/class wrapping, but it overshoots on every nested statement.
    Fixed by `locate_enclosing_function`: walk outermost-inward and skip wrapper
    constructs explicitly instead of hiding from them.

B2  The vulnerable side was sliced *literally* from `scope.start`/`scope.end`
    while the fixed side was brace-matched. Those ranges are frequently not
    function boundaries (`D/C/1222` has scope.start=131, a statement
    continuation line deep inside a body), so the slice ran past the target
    function into the next one. Fixed by anchoring and brace-matching both sides
    identically; the scope range is now a hint, never a boundary.

B3  `count_top_level_braces` only counts *matched* brace pairs, so a slice
    ending in an unclosed '{' was never flagged - exactly the over-extension
    B2 produces. That is why contaminated cases carried `extraction_status:
    "ok"`. Fixed by `is_single_clean_function`, which also requires that nothing
    follows the function's closing brace.

Every scope entry is written out with a status, mirroring the published
extractor, so the file set is a complete audit trail and `run_cases_local.py`
(which selects on `extraction_status == "ok"`) can consume it unchanged.

Usage: python3 experiments/2026-08-22_extraction-v2/extract_v2.py [--out DIR]
"""
import argparse
import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

# Reuse the sound helpers from the published extractor rather than keeping a
# second, subtly different copy. Importing is read-only; the same pattern is
# used by experiments/common/data.py for compute_metrics.py.
from extract_cases import (  # noqa: E402
    LEAKAGE_WORDS,
    back_up_to_signature_start,
    compute_brace_pairs,
    match_scope_to_changed_lines,
    split_lines_strict,
)

ZIP_PATH = ROOT / "D.zip"
DEFAULT_OUT = HERE / "cases_v2"

# A construct whose body is *not* a function body. Matched on the signature text
# preceding a '{'. The `"(" not in header` test is what separates
# `class Foo : public Bar {` from `void f(struct Foo *x) {` - a function
# signature always carries a parameter list, a namespace/class header never does.
WRAPPER_RE = re.compile(r"\b(namespace|class|struct|union|enum)\b")

FUNC_NAME_RE = re.compile(r"(\w+)\s*\(")

# Identifiers that can precede '(' in a signature line without being the
# function name: control keywords (from a preceding statement the signature
# back-up may have swept in), and the attribute/assert macros common in kernel
# and Chromium sources.
NON_NAME_IDENTS = {
    "if", "for", "while", "switch", "return", "sizeof", "do", "else", "case",
    "defined", "typeof", "__attribute__", "static_assert", "COMPILE_ASSERT",
    "alignas", "decltype", "noexcept",
}


def looks_like_wrapper(header):
    """True if `header` (signature text preceding a '{') opens a namespace,
    class, struct, union, enum or `extern "C"` block rather than a function."""
    h = header.strip()
    if not h:
        return False
    if "(" in h:
        return False
    if h.startswith("extern"):
        return True
    return bool(WRAPPER_RE.search(h))


def looks_like_macro(header):
    """True if `header` is a preprocessor directive rather than a signature.

    A multi-line `#define` whose body is a GCC statement expression - `#define
    m(x) ({ ... })` - presents a brace pair with a `name(args)` header, so it is
    otherwise indistinguishable from a function. `C_701__0`
    (`arch_timer_reg_read_stable`) is one; there is no function to reconstruct
    from a docstring, so it is dropped rather than emitted.
    """
    return any(l.lstrip().startswith("#") for l in header.splitlines())


def locate_enclosing_function(text, brace_pairs, anchor_idx):
    """Return (start_idx, end_idx, open_idx) of the function enclosing
    `anchor_idx`, including its signature line(s).

    Walks the enclosing brace pairs from **outermost inward** and returns the
    first that is not a wrapper construct. The published extractor took the
    innermost pair, which returns whatever `if`/`while`/`for` block the patched
    line happens to sit in (B1).
    """
    enclosing = [(s, e) for s, e in brace_pairs if s < anchor_idx < e]
    if not enclosing:
        return None
    enclosing.sort(key=lambda p: -(p[1] - p[0]))  # outermost first
    for open_idx, end_idx in enclosing:
        start_idx = back_up_to_signature_start(text, open_idx)
        if looks_like_wrapper(text[start_idx:open_idx]):
            continue
        return start_idx, end_idx, open_idx
    # Every level looked like a wrapper (e.g. a member initialiser inside a
    # class body); fall back to the innermost rather than dropping the case.
    open_idx, end_idx = enclosing[-1]
    return back_up_to_signature_start(text, open_idx), end_idx, open_idx


def function_name(text, start_idx, open_idx):
    """First identifier followed by '(' in the signature text that is not a
    keyword. Earlier tokens are the return type and storage qualifiers, which
    do not carry a parameter list."""
    names = [n for n in FUNC_NAME_RE.findall(text[start_idx:open_idx])
             if n not in NON_NAME_IDENTS]
    return names[0] if names else None


def top_level_pairs(snippet):
    pairs = compute_brace_pairs(snippet)
    return sorted(
        (s, e) for i, (s, e) in enumerate(pairs)
        if not any(j != i and pairs[j][0] < s and e < pairs[j][1]
                   for j in range(len(pairs)))
    )


def is_single_clean_function(snippet):
    """Exactly one complete top-level function, a signature before it, and
    nothing glued on after its closing brace.

    Replaces `count_top_level_braces`, which counted only *matched* pairs and so
    silently accepted `target_function + truncated fragment of the next one`
    (B3) - the single most common defect in the published corpus.
    """
    top = top_level_pairs(snippet)
    if len(top) != 1:
        return False
    open_idx, end_idx = top[0]
    if snippet[end_idx:].strip():
        return False
    return bool(snippet[:open_idx].strip())


def line_offsets(text):
    offs = [0]
    for line in split_lines_strict(text):
        offs.append(offs[-1] + len(line))
    return offs


def offset_of_line(offs, line_no):
    return offs[min(max(line_no - 1, 0), len(offs) - 1)]


def locate_with_fallbacks(text, brace_pairs, anchors):
    """Try each candidate anchor in turn, then retry each at the next '{' after
    it. The retry catches hunks whose first line sits at file scope immediately
    above the function they modify (a blank line, a comment banner, or the
    signature itself).

    Returns (location, func_name, strategy) or (None, None, None).
    """
    for anchor in anchors:
        loc = locate_enclosing_function(text, brace_pairs, anchor)
        if loc:
            name = function_name(text, loc[0], loc[2])
            if name:
                return loc, name, "direct"
    for anchor in anchors:
        nxt = text.find("{", anchor)
        if nxt == -1:
            continue
        loc = locate_enclosing_function(text, brace_pairs, nxt + 1)
        if loc:
            name = function_name(text, loc[0], loc[2])
            if name:
                return loc, name, "next-brace"
    return None, None, None


def locate_fixed_by_name(fixed_text, brace_pairs, func_name_):
    """Last resort for the fixed side: find the definition of `func_name_`
    (a '(' ... '{' with no intervening ';') and brace-match around it."""
    m = re.search(r"\b" + re.escape(func_name_) + r"\s*\([^;{]*\{", fixed_text)
    if not m:
        return None
    return locate_enclosing_function(fixed_text, brace_pairs, m.end())


def blank_record(case_id, sample_id, si, language, data, docstring, scope_entry):
    return {
        "case_id": case_id,
        "sample_id": sample_id,
        "func_idx": si,
        "language": language,
        "repo": data.get("repo"),
        "cve_id": data.get("cve_id"),
        "cve_summary": data.get("cve_summary"),
        "commit_message": data.get("commit_message"),
        "changed_file": data.get("changed_file"),
        "docstring": docstring,
        "heuristic_leakage_flag": bool(LEAKAGE_WORDS.search(docstring or "")),
        "scope_line_range": [scope_entry["start"], scope_entry["end"]],
        "vulnerable_line_range": None,
        "vulnerable_snippet": None,
        "fixed_line_range": None,
        "fixed_snippet": None,
        "func_name": None,
        "extraction_status": None,
        "extraction_reason": None,
        "extraction_method": "v2",
        "anchor_strategy": None,
        "duplicate_of": None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="output directory")
    args = ap.parse_args()
    out_dir = Path(args.out)

    out_dir.mkdir(parents=True, exist_ok=True)
    for f in out_dir.glob("*.json"):
        f.unlink()

    zf = zipfile.ZipFile(ZIP_PATH)
    config_paths = sorted(n for n in zf.namelist() if n.endswith("config.json"))

    stats = Counter()
    anchor_stats = Counter()
    records = []
    # (repo, cve_id, vulnerable_snippet) -> first case_id that produced it
    first_seen = {}

    for cfg_path in config_paths:
        data = json.loads(zf.read(cfg_path))
        parts = cfg_path.split("/")  # D, C or C++, <id>, config.json
        lang_dir, sample_num = parts[1], parts[2]
        language = "cpp" if lang_dir == "C++" else "c"
        ext = "cpp" if language == "cpp" else "c"

        vuln_text = zf.read(f"D/{lang_dir}/{sample_num}/vulnerable.{ext}").decode("utf-8", "replace")
        fixed_text = zf.read(f"D/{lang_dir}/{sample_num}/fixed.{ext}").decode("utf-8", "replace")
        vuln_pairs = compute_brace_pairs(vuln_text)
        fixed_pairs = compute_brace_pairs(fixed_text)
        vuln_offs = line_offsets(vuln_text)
        fixed_offs = line_offsets(fixed_text)

        scope = data.get("scope", [])
        changed_lines = data.get("changed_lines", [])
        matched = match_scope_to_changed_lines(scope, changed_lines)

        for si, s in enumerate(scope):
            case_id = f"{lang_dir.replace('+', 'p')}_{sample_num}__{si}"
            rec = blank_record(case_id, f"D/{lang_dir}/{sample_num}", si,
                               language, data, s.get("docstring"), s)
            stats["total_scope_entries"] += 1

            def fail(status, reason):
                rec["extraction_status"] = status
                rec["extraction_reason"] = reason
                stats[status] += 1
                records.append(rec)

            if si not in matched:
                fail("skipped_no_changed_lines_overlap",
                     "no changed_lines entry overlaps this scope range")
                continue

            cl = changed_lines[matched[si]]
            hunk_start = cl["original_lines"]["start"]
            hunk_end = hunk_start + cl["original_lines"]["count"] - 1
            fixed_hunk_start = cl["fixed_lines"]["start"]
            fixed_hunk_mid = fixed_hunk_start + cl["fixed_lines"]["count"] // 2

            # Anchor candidates, most reliable first. The scope range is a hint
            # only; B2 is precisely the assumption that it is a boundary.
            vuln_anchors = [offset_of_line(vuln_offs, ln) for ln in (
                hunk_start,
                (hunk_start + hunk_end) // 2,
                (s["start"] + s["end"]) // 2,
                s["start"],
            )]
            fixed_anchors = [offset_of_line(fixed_offs, ln)
                             for ln in (fixed_hunk_start, fixed_hunk_mid)]

            vuln_loc, func_name_, vuln_strategy = locate_with_fallbacks(
                vuln_text, vuln_pairs, vuln_anchors)
            if vuln_loc is None:
                fail("skipped_anchor_not_in_function",
                     "the patched line is at file scope (include block, global "
                     "declaration or class body), so there is no enclosing function")
                continue

            fixed_loc, _, fixed_strategy = locate_with_fallbacks(
                fixed_text, fixed_pairs, fixed_anchors)
            vuln_snippet = vuln_text[vuln_loc[0]:vuln_loc[1]]
            fixed_snippet = fixed_text[fixed_loc[0]:fixed_loc[1]] if fixed_loc else ""

            # Identifier agreement: the two sides must be the same function.
            if not re.search(r"\b" + re.escape(func_name_) + r"\s*\(", fixed_snippet):
                by_name = locate_fixed_by_name(fixed_text, fixed_pairs, func_name_)
                if by_name is None:
                    fail("skipped_fixed_function_not_found",
                         f"function '{func_name_}' not found in fixed.{ext} via "
                         "anchor or name search")
                    continue
                fixed_loc, fixed_strategy = by_name, "name-search"
                fixed_snippet = fixed_text[fixed_loc[0]:fixed_loc[1]]

            rec["func_name"] = func_name_
            rec["anchor_strategy"] = {"vulnerable": vuln_strategy, "fixed": fixed_strategy}

            if looks_like_macro(vuln_snippet[:vuln_snippet.find("{")]):
                fail("skipped_macro_not_function",
                     f"'{func_name_}' is a preprocessor macro with a statement-"
                     "expression body, not a function")
                continue

            if not is_single_clean_function(vuln_snippet):
                fail("skipped_vulnerable_not_single_function",
                     "extracted vulnerable side is not exactly one complete function")
                continue
            if not is_single_clean_function(fixed_snippet):
                fail("skipped_fixed_not_single_function",
                     "extracted fixed side is not exactly one complete function")
                continue

            vuln_start_line = vuln_text.count("\n", 0, vuln_loc[0]) + 1
            vuln_end_line = vuln_start_line + vuln_snippet.count("\n")
            if not (vuln_start_line <= hunk_start and hunk_end <= vuln_end_line):
                fail("skipped_hunk_not_contained",
                     f"changed lines {hunk_start}-{hunk_end} are not fully inside "
                     f"the extracted function ({vuln_start_line}-{vuln_end_line})")
                continue

            if vuln_snippet.strip() == fixed_snippet.strip():
                fail("skipped_patch_did_not_touch_function",
                     "vulnerable and fixed snippets are identical")
                continue

            if not (s.get("docstring") or "").strip():
                fail("skipped_empty_docstring", "scope entry carries no docstring")
                continue

            fixed_start_line = fixed_text.count("\n", 0, fixed_loc[0]) + 1
            rec.update({
                "vulnerable_line_range": [vuln_start_line, vuln_end_line],
                "vulnerable_snippet": vuln_snippet,
                "fixed_line_range": [fixed_start_line,
                                     fixed_start_line + fixed_snippet.count("\n")],
                "fixed_snippet": fixed_snippet,
                "extraction_status": "ok",
                "extraction_reason": None,
            })

            # The dataset emits the same function twice when it generated two
            # docstrings for it (D/C/1222 scope 0 and 1 share range 131-204).
            # Both are kept - the docstring variants are a usable signal - but
            # flagged so metrics can drop them without losing that.
            key = (data.get("repo"), data.get("cve_id"), vuln_snippet)
            if key in first_seen:
                rec["duplicate_of"] = first_seen[key]
                stats["ok_duplicate"] += 1
            else:
                first_seen[key] = case_id

            stats["ok"] += 1
            anchor_stats[f"vulnerable:{vuln_strategy}"] += 1
            anchor_stats[f"fixed:{fixed_strategy}"] += 1
            records.append(rec)

    # Self-check: the guard must hold on every emitted case by construction.
    bad = [r["case_id"] for r in records if r["extraction_status"] == "ok"
           and not (is_single_clean_function(r["vulnerable_snippet"])
                    and is_single_clean_function(r["fixed_snippet"]))]
    if bad:
        sys.exit(f"FATAL: {len(bad)} emitted cases fail is_single_clean_function: {bad[:5]}")

    for rec in records:
        (out_dir / f"{rec['case_id']}.json").write_text(
            json.dumps(rec, indent=2), encoding="utf-8")

    print(f"wrote {len(records)} case files to {out_dir}")
    print(json.dumps(dict(sorted(stats.items())), indent=2))
    print("\nanchor strategies (ok cases):")
    for k, v in sorted(anchor_stats.items()):
        print(f"  {k:24s} {v}")
    unique = stats["ok"] - stats["ok_duplicate"]
    print(f"\nusable: {stats['ok']} cases, {unique} unique (repo, cve, function)")


if __name__ == "__main__":
    main()
