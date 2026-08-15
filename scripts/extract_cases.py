"""Parsing helpers for reading D.zip - a library, with no entry point.

The corpus is built by `scripts/extract_v2.py` and checked by
`scripts/validate_corpus.py`; both import from here rather than keeping their
own copy of the brace matching, so the extractor cannot drift from the
validator that gates it.

What lives here:

  - `split_lines_strict` / `compute_brace_pairs`: line splitting that survives
    the mixed line endings in the archive, and a brace matcher that ignores
    braces inside strings, character literals and comments.
  - `match_scope_to_changed_lines`: pairs a documented function with the
    `changed_lines` entry it belongs to by line-range overlap, not by list
    position - multi-function commits do not list the two in the same order.
  - `back_up_to_signature_start`: walks back from a function's opening brace
    over the return type, attributes and parameter list to the true start of
    the signature.
  - `LEAKAGE_WORDS`: the heuristic that flags a docstring which may be
    describing the fix rather than the function.

Line numbers shift between the two sides of a patch, so the fixed-side function
is always located by name and brace matching rather than by offsetting the
vulnerable-side range.
"""
import re

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
