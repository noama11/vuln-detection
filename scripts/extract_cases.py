"""
Extracts one case file per function-level scope entry from D.zip.

For each D/{C,C++}/{id}/config.json:
  - match each `scope` entry (a documented function, vulnerable.<ext> line numbers)
    to the `changed_lines` entry it belongs to, via line-range overlap (not
    list position - multi-function commits are not guaranteed to list scope
    and changed_lines in the same order).
  - extract the vulnerable-side snippet directly via scope.start/end.
  - locate + extract the same function in fixed.<ext> by function-name search
    + brace counting (line numbers shift because the fix inserts/removes lines,
    so a naive offset shift is wrong).

Read-only w.r.t. D.zip. Writes one JSON file per case to cases/.
"""
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ZIP_PATH = ROOT / "D.zip"
OUT_DIR = ROOT / "cases"

LEAKAGE_WORDS = re.compile(
    r"\b(prevent|avoid|mitigat\w*|sanitiz\w*|protect\w*\s+against|guard\w*\s+against)\b",
    re.IGNORECASE,
)

FUNC_NAME_RE = re.compile(r"^\s*[\w\*\s]*?\b(\w+)\s*\(", re.MULTILINE)


def split_lines_strict(text):
    """Split on '\\n' only, matching diff/line-numbering tools - unlike
    str.splitlines(), which also breaks on \\v, \\f, \\x1c-\\x1e, \\x85,
    \\u2028, \\u2029 and silently shifts line numbers (and thus every
    downstream offset) when a source file contains any of those bytes."""
    lines = text.split("\n")
    return [l + "\n" for l in lines[:-1]] + ([lines[-1]] if lines[-1] else [])


def overlap_len(a_start, a_end, b_start, b_end):
    lo = max(a_start, b_start)
    hi = min(a_end, b_end)
    return max(0, hi - lo + 1)


def match_scope_to_changed_lines(scope, changed_lines):
    """Greedy max-overlap bipartite matching between scope entries and
    changed_lines entries, using vulnerable-side ranges for both."""
    candidates = []
    for si, s in enumerate(scope):
        for ci, cl in enumerate(changed_lines):
            ol = cl["original_lines"]
            ov = overlap_len(s["start"], s["end"], ol["start"], ol["start"] + ol["count"] - 1)
            if ov > 0:
                candidates.append((ov, si, ci))
    candidates.sort(key=lambda x: -x[0])
    used_s, used_c = set(), set()
    matched = {}
    for ov, si, ci in candidates:
        if si in used_s or ci in used_c:
            continue
        matched[si] = ci
        used_s.add(si)
        used_c.add(ci)
    return matched


def extract_function_name(snippet_text):
    m = FUNC_NAME_RE.search(snippet_text)
    return m.group(1) if m else None


def compute_brace_pairs(text):
    """Single pass over the file collecting every matched (open_idx, end_idx)
    brace pair, skipping string/char literals and comments. end_idx is the
    index just after the closing '}'."""
    pairs = []
    stack = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i)
            i = nl if nl != -1 else n
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = end + 2 if end != -1 else n
            continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\":
                    j += 1
                j += 1
            i = j + 1
            continue
        if c == "'":
            j = i + 1
            while j < n and text[j] != "'":
                if text[j] == "\\":
                    j += 1
                j += 1
            i = j + 1
            continue
        if c == "{":
            stack.append(i)
        elif c == "}":
            if stack:
                start = stack.pop()
                pairs.append((start, i + 1))
        i += 1
    return pairs


def back_up_to_signature_start(text, brace_open_idx):
    """From the '{' that opens a function body, walk backward over any
    immediately preceding lines that look like a continuation of the
    signature (return type / storage class / parameter wrap)."""
    line_start = text.rfind("\n", 0, brace_open_idx)
    line_start = 0 if line_start == -1 else line_start + 1
    start_idx = line_start
    while True:
        prev_nl = text.rfind("\n", 0, start_idx - 1)
        prev_line_start = 0 if prev_nl == -1 else prev_nl + 1
        prev_line = text[prev_line_start:start_idx - 1] if start_idx > 0 else ""
        stripped = prev_line.strip()
        if stripped and not stripped.endswith((";", "}", "{", "*/")) and not stripped.startswith(("//", "/*", "*")):
            start_idx = prev_line_start
        else:
            break
    return start_idx


def count_top_level_braces(text):
    """Count brace pairs in `text` not nested inside any other pair found in
    `text`. A single-function slice has exactly one (the function's own
    body); a scope entry spanning multiple functions/declarations has more,
    since each sits at the same nesting depth relative to the slice."""
    pairs = compute_brace_pairs(text)
    top_level = 0
    for i, (s, e) in enumerate(pairs):
        contained = any(j != i and pairs[j][0] < s and e < pairs[j][1] for j in range(len(pairs)))
        if not contained:
            top_level += 1
    return top_level


def locate_function_by_anchor(fixed_text, brace_pairs, anchor_idx):
    """Finds the innermost brace pair strictly containing anchor_idx (this
    is robust to C++ namespace/class wrapping, unlike a naive top-level-only
    scan) and returns (start_idx, end_idx) of the enclosing function,
    including its signature line(s)."""
    best = None
    for start, end in brace_pairs:
        if start < anchor_idx < end:
            if best is None or (end - start) < (best[1] - best[0]):
                best = (start, end)
    if best is None:
        return None
    open_idx, end_idx = best
    start_idx = back_up_to_signature_start(fixed_text, open_idx)
    return start_idx, end_idx


def locate_function_by_name(fixed_text, func_name):
    """Fallback: find `func_name(` followed eventually by '{' before any
    ';', then brace-count to the matching close."""
    if not func_name:
        return None
    pairs = compute_brace_pairs(fixed_text)
    pattern = re.compile(r"\b" + re.escape(func_name) + r"\s*\(")
    for m in pattern.finditer(fixed_text):
        search_from = m.end()
        window_end = min(len(fixed_text), search_from + 2000)
        brace_pos = None
        for j in range(search_from, window_end):
            ch = fixed_text[j]
            if ch == ";":
                break
            if ch == "{":
                brace_pos = j
                break
        if brace_pos is None:
            continue
        match = next((p for p in pairs if p[0] == brace_pos), None)
        if match is None:
            continue
        start_idx = back_up_to_signature_start(fixed_text, brace_pos)
        return start_idx, match[1]
    return None


def main():
    OUT_DIR.mkdir(exist_ok=True)
    for f in OUT_DIR.glob("*.json"):
        f.unlink()

    zf = zipfile.ZipFile(ZIP_PATH)
    config_paths = sorted(n for n in zf.namelist() if n.endswith("config.json"))

    stats = {
        "total_scope_entries": 0,
        "written": 0,
        "skipped_no_overlap": 0,
        "skipped_fixed_not_found": 0,
        "skipped_multi_function_scope": 0,
        "suspect_identifier_mismatch": 0,
    }

    for cfg_path in config_paths:
        data = json.loads(zf.read(cfg_path))
        parts = cfg_path.split("/")  # D, C or C++, <id>, config.json
        lang_dir = parts[1]
        sample_num = parts[2]
        language = "cpp" if lang_dir == "C++" else "c"
        ext = "cpp" if language == "cpp" else "c"

        vuln_path = f"D/{lang_dir}/{sample_num}/vulnerable.{ext}"
        fixed_path = f"D/{lang_dir}/{sample_num}/fixed.{ext}"
        vuln_lines = split_lines_strict(zf.read(vuln_path).decode("utf-8", errors="replace"))
        fixed_text = zf.read(fixed_path).decode("utf-8", errors="replace")
        fixed_brace_pairs = compute_brace_pairs(fixed_text)

        fixed_line_offsets = [0]
        for line in split_lines_strict(fixed_text):
            fixed_line_offsets.append(fixed_line_offsets[-1] + len(line))

        scope = data.get("scope", [])
        changed_lines = data.get("changed_lines", [])
        matched = match_scope_to_changed_lines(scope, changed_lines)

        for si, s in enumerate(scope):
            stats["total_scope_entries"] += 1
            case_id = f"{lang_dir.replace('+', 'p')}_{sample_num}__{si}"

            vulnerable_snippet = "".join(vuln_lines[s["start"] - 1:s["end"]])
            func_name = extract_function_name(vulnerable_snippet)

            record = {
                "case_id": case_id,
                "sample_id": f"D/{lang_dir}/{sample_num}",
                "func_idx": si,
                "language": language,
                "repo": data.get("repo"),
                "cve_id": data.get("cve_id"),
                "cve_summary": data.get("cve_summary"),
                "commit_message": data.get("commit_message"),
                "changed_file": data.get("changed_file"),
                "docstring": s.get("docstring"),
                "heuristic_leakage_flag": bool(LEAKAGE_WORDS.search(s.get("docstring") or "")),
                "vulnerable_line_range": [s["start"], s["end"]],
                "vulnerable_snippet": vulnerable_snippet,
                "extraction_status": "ok",
                "extraction_reason": None,
                "fixed_line_range": None,
                "fixed_snippet": None,
            }

            top_level_count = count_top_level_braces(vulnerable_snippet)

            if top_level_count > 1:
                record["extraction_status"] = "unsupported_multi_function_scope"
                record["extraction_reason"] = (
                    f"vulnerable-side scope spans {top_level_count} top-level "
                    "constructs (functions/declarations), not a single function"
                )
                stats["skipped_multi_function_scope"] += 1
            elif si not in matched:
                record["extraction_status"] = "skipped"
                record["extraction_reason"] = "no overlapping changed_lines entry"
                stats["skipped_no_overlap"] += 1
            else:
                cl = changed_lines[matched[si]]
                anchor_line = cl["fixed_lines"]["start"]
                anchor_idx = fixed_line_offsets[min(anchor_line - 1, len(fixed_line_offsets) - 1)]

                loc = locate_function_by_anchor(fixed_text, fixed_brace_pairs, anchor_idx)
                if loc is None:
                    loc = locate_function_by_name(fixed_text, func_name)
                if loc is None:
                    record["extraction_status"] = "skipped"
                    record["extraction_reason"] = f"function '{func_name}' not found via anchor or name in fixed.{ext}"
                    stats["skipped_fixed_not_found"] += 1
                else:
                    start_idx, end_idx = loc
                    fixed_snippet = fixed_text[start_idx:end_idx]
                    record["fixed_snippet"] = fixed_snippet
                    # approximate 1-indexed line range for reference/debugging
                    line_start = fixed_text.count("\n", 0, start_idx) + 1
                    line_end = line_start + fixed_snippet.count("\n")
                    record["fixed_line_range"] = [line_start, line_end]

                    if func_name and not re.search(r"\b" + re.escape(func_name) + r"\b", fixed_snippet):
                        record["extraction_status"] = "suspect_identifier_mismatch"
                        record["extraction_reason"] = (
                            f"located fixed-side function does not contain identifier '{func_name}'"
                        )
                        stats["suspect_identifier_mismatch"] += 1

            (OUT_DIR / f"{case_id}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
            stats["written"] += 1

    print(json.dumps(stats, indent=2))
    ok = (
        stats["written"]
        - stats["skipped_no_overlap"]
        - stats["skipped_fixed_not_found"]
        - stats["skipped_multi_function_scope"]
        - stats["suspect_identifier_mismatch"]
    )
    print(f"Fully extracted (both sides ok): {ok}/{stats['total_scope_entries']}")


if __name__ == "__main__":
    main()
