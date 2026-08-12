"""
Cheap, no-LLM-cost audit of which side of the vulnerable/fixed diff each
docstring's language actually leans toward.

Motivation: `heuristic_leakage_flag` (in extract_cases.py) only catches one
leakage direction - a docstring narrating protective/defensive language
("prevents overflow", "sanitizes") despite being anchored to the vulnerable
side. It does not catch the mirror-image and structurally more common case:
a docstring that's simply a literal paraphrase of the vulnerable code's
exact logic, which will differ from the fixed side for reasons that have
nothing to do with the model exercising any security judgment.

Method (pure stdlib, no API calls):
  1. Line-diff vulnerable_snippet vs fixed_snippet (difflib) to find the
     tokens that only exist on the vulnerable side ("removed-only") and the
     tokens that only exist on the fixed side ("added-only") - i.e. the
     actual delta the fix introduced.
  2. Tokenize the docstring into identifier/word tokens.
  3. Score how much the docstring's tokens overlap with removed-only vs
     added-only tokens (restricted to tokens that are distinctive - not
     generic code/English filler - so shared boilerplate like "if"/"return"
     doesn't dominate).
  4. Classify each case: vulnerable_echo (docstring specifically describes
     removed-only logic), fix_leak (docstring specifically describes
     added-only logic), or neutral (neither, or both weakly).

This is a heuristic screen, not a verdict - it is meant to size the problem
and prioritize candidates for a follow-up LLM-based check, not to replace
one. Writes reports/docstring_alignment_audit.md + a full per-case CSV.

Usage: python scripts/audit_docstring_alignment.py [ok|all]
  ok  (default) - only cases with extraction_status == "ok"
  all - every case with both snippets present (any status)
"""
import csv
import difflib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = ROOT / "cases"

TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Generic tokens (code boilerplate + common English) that shouldn't count as
# "distinctive" evidence either way - without this, "return"/"the"/"if"
# would swamp every case's overlap score regardless of real content.
STOPWORDS = {
    "the", "a", "an", "is", "are", "if", "else", "return", "void", "int",
    "char", "const", "static", "inline", "struct", "this", "then", "to",
    "of", "and", "or", "not", "null", "true", "false", "for", "while",
    "it", "its", "in", "on", "at", "by", "with", "from", "that", "as",
    "be", "will", "which", "function", "value", "data", "size", "field",
    "fields", "parameter", "parameters", "returns", "return", "summary",
    "logic", "successful", "success", "failure", "result", "when", "into",
}


def tokenize(text):
    return {t.lower() for t in TOKEN_RE.findall(text or "") if len(t) >= 3} - STOPWORDS


def diff_only_tokens(vulnerable_snippet, fixed_snippet):
    """Returns (removed_only_tokens, added_only_tokens) - tokens that appear
    in a diff-changed line unique to one side, minus tokens shared by both
    full snippets (so identifiers used throughout, like `image`/`pixel`,
    never count as "distinctive" even though they're technically on a
    changed line)."""
    v_lines = vulnerable_snippet.splitlines()
    f_lines = fixed_snippet.splitlines()
    sm = difflib.SequenceMatcher(a=v_lines, b=f_lines, autojunk=False)

    removed_text, added_text = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("delete", "replace"):
            removed_text.extend(v_lines[i1:i2])
        if tag in ("insert", "replace"):
            added_text.extend(f_lines[j1:j2])

    removed_tokens = tokenize("\n".join(removed_text))
    added_tokens = tokenize("\n".join(added_text))
    shared_everywhere = tokenize(vulnerable_snippet) & tokenize(fixed_snippet)

    removed_only = removed_tokens - added_tokens - shared_everywhere
    added_only = added_tokens - removed_tokens - shared_everywhere
    return removed_only, added_only


def classify(docstring, vulnerable_snippet, fixed_snippet):
    removed_only, added_only = diff_only_tokens(vulnerable_snippet, fixed_snippet)
    doc_tokens = tokenize(docstring)

    vuln_hits = doc_tokens & removed_only
    fix_hits = doc_tokens & added_only

    n_vuln, n_fix = len(vuln_hits), len(fix_hits)
    if n_vuln == 0 and n_fix == 0:
        label = "neutral_no_distinctive_overlap"
    elif n_vuln > 0 and n_fix == 0:
        label = "vulnerable_echo"
    elif n_fix > 0 and n_vuln == 0:
        label = "fix_leak"
    elif n_vuln > n_fix:
        label = "vulnerable_echo_leaning"
    elif n_fix > n_vuln:
        label = "fix_leak_leaning"
    else:
        label = "ambiguous_both"

    return {
        "label": label,
        "vuln_hits": sorted(vuln_hits),
        "fix_hits": sorted(fix_hits),
        "removed_only_count": len(removed_only),
        "added_only_count": len(added_only),
    }


def main():
    scope = sys.argv[1] if len(sys.argv) > 1 else "ok"

    rows = []
    for fp in sorted(CASES_DIR.glob("*.json")):
        d = json.loads(fp.read_text(encoding="utf-8"))
        if scope == "ok" and d["extraction_status"] != "ok":
            continue
        if not d.get("vulnerable_snippet") or not d.get("fixed_snippet"):
            continue

        result = classify(d["docstring"], d["vulnerable_snippet"], d["fixed_snippet"])
        rows.append({
            "case_id": d["case_id"],
            "repo": d["repo"],
            "cve_id": d["cve_id"],
            "heuristic_leakage_flag": d["heuristic_leakage_flag"],
            **result,
        })

    from collections import Counter
    counts = Counter(r["label"] for r in rows)
    total = len(rows)

    lines = [f"# Docstring alignment audit ({scope} cases)", ""]
    lines.append(f"Total cases scanned: {total}")
    lines.append("")
    lines.append("## Label distribution")
    for label in ["vulnerable_echo", "vulnerable_echo_leaning", "fix_leak",
                  "fix_leak_leaning", "ambiguous_both", "neutral_no_distinctive_overlap"]:
        n = counts.get(label, 0)
        pct = (n / total * 100) if total else 0
        lines.append(f"- **{label}**: {n} ({pct:.1f}%)")
    lines.append("")

    vuln_leaning = sum(counts.get(l, 0) for l in ("vulnerable_echo", "vulnerable_echo_leaning"))
    fix_leaning = sum(counts.get(l, 0) for l in ("fix_leak", "fix_leak_leaning"))
    lines.append(f"**Any vulnerable-echo lean**: {vuln_leaning} ({vuln_leaning/total*100:.1f}%)")
    lines.append(f"**Any fix-leak lean**: {fix_leaning} ({fix_leaning/total*100:.1f}%)")
    lines.append("")

    existing_flag_true = [r for r in rows if r["heuristic_leakage_flag"]]
    lines.append(f"## Cross-check vs existing `heuristic_leakage_flag` ({len(existing_flag_true)} flagged)")
    overlap = Counter(r["label"] for r in existing_flag_true)
    for label, n in overlap.most_common():
        lines.append(f"- flagged-by-regex AND `{label}`: {n}")
    lines.append("")
    lines.append(
        "(If the regex-based flag and `fix_leak*` labels barely overlap, the "
        "two mechanisms are catching different things and both are worth "
        "keeping; if they overlap heavily, the new check is mostly redundant.)"
    )
    lines.append("")

    lines.append("## Sample cases per label (first 5 each)")
    for label in ["vulnerable_echo", "fix_leak", "fix_leak_leaning", "vulnerable_echo_leaning"]:
        examples = [r for r in rows if r["label"] == label][:5]
        if not examples:
            continue
        lines.append(f"\n### {label}")
        for r in examples:
            lines.append(
                f"- `{r['case_id']}` ({r['repo']}, {r['cve_id']}) - "
                f"vuln_hits={r['vuln_hits']}, fix_hits={r['fix_hits']}"
            )

    report_path = ROOT / "reports" / "docstring_alignment_audit.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")

    csv_path = ROOT / "reports" / "docstring_alignment_audit.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "case_id", "repo", "cve_id", "heuristic_leakage_flag", "label",
            "vuln_hits", "fix_hits", "removed_only_count", "added_only_count",
        ])
        writer.writeheader()
        for r in rows:
            row = dict(r)
            row["vuln_hits"] = ";".join(row["vuln_hits"])
            row["fix_hits"] = ";".join(row["fix_hits"])
            writer.writerow(row)

    print(f"Wrote {report_path}")
    print(f"Wrote {csv_path}")
    print()
    print("\n".join(lines))


if __name__ == "__main__":
    main()
