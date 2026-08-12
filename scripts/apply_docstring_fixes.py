"""
Applies the LLM audit's confirmed-leak rewrites (reports/docstring_audit/) back
into cases/*.json's `docstring` field.

`rewritten_docstring` in each audit result is a replacement for only the
`Logic:` paragraph, not the whole docstring (see
prompts/docstring_leakage_audit_system_prompt.txt) - Summary/Parameters/
Returns are left untouched. Docstrings in this corpus come in several
formats (plain, triple-quoted, C-block-comment `/** ... */`, banner-style
`/****...****/`), so this does a structural splice rather than a blind
string replace:

  1. Detect the line-prefix style (e.g. " * ") from the docstring's own
     `Summary:` line, so the replacement matches the surrounding format.
  2. Find the `Logic:` line and the closing wrapper (if any - a triple-quote,
     `*/`, or an asterisk banner line), preserving everything outside that
     span verbatim.
  3. Rebuild the Logic section from `rewritten_docstring`, word-wrapped to
     match the original's line width when a comment prefix is present.

This is a formatting best-effort, not a guarantee of pixel-identical
cosmetics - the field is consumed purely as spec text by the pipeline, never
parsed as a real comment, so a minor wrap-width mismatch is harmless. Cases
where the `Logic:` marker can't be located are left untouched and reported,
not silently skipped-and-forgotten.

Read-only w.r.t. reports/docstring_audit/; writes only the `docstring` field
of cases/<case_id>.json (every other field, including extraction metadata,
is left alone).

Usage: python scripts/apply_docstring_fixes.py [--dry-run]
"""
import argparse
import json
import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = ROOT / "reports" / "docstring_audit"
CASES_DIR = ROOT / "cases"

SUMMARY_RE = re.compile(r'^(?P<prefix>[\s*/]*)Summary\s*:', re.IGNORECASE)
LOGIC_RE = re.compile(r'^(?P<prefix>[\s*/]*)Logic\s*:\s*(?P<inline>.*)$', re.IGNORECASE)
CLOSE_RE = re.compile(r'^\s*(\*+/|""")\s*$')


def splice_logic(docstring, rewritten):
    lines = docstring.split("\n")

    prefix = ""
    m = SUMMARY_RE.match(next((l for l in lines if SUMMARY_RE.match(l)), ""))
    if m:
        prefix = m.group("prefix")

    logic_idx = None
    inline = ""
    for i, line in enumerate(lines):
        m = LOGIC_RE.match(line)
        if m:
            logic_idx = i
            inline = m.group("inline")
            break
    if logic_idx is None:
        return None  # couldn't locate the Logic section - caller flags this

    end_idx = len(lines)
    for j in range(logic_idx + 1, len(lines)):
        if CLOSE_RE.match(lines[j]):
            end_idx = j
            break

    if prefix.strip():  # comment-style prefix (e.g. " * ") - wrap to match
        width = max(40, 100 - len(prefix))
        wrapped = textwrap.wrap(rewritten, width=width) or [""]
        if inline:
            new_lines = [f"{prefix}Logic: {wrapped[0]}"] + [f"{prefix}{w}" for w in wrapped[1:]]
        else:
            new_lines = [f"{prefix}Logic:"] + [f"{prefix}{w}" for w in wrapped]
    else:
        new_lines = [f"Logic: {rewritten}"]

    return "\n".join(lines[:logic_idx] + new_lines + lines[end_idx:])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="show what would change without writing")
    args = ap.parse_args()

    applied, failed = [], []
    for fp in sorted(AUDIT_DIR.glob("*.json")):
        audit = json.loads(fp.read_text(encoding="utf-8"))
        if audit["verdict"] != "confirmed_leak" or not audit.get("rewritten_docstring"):
            continue
        cid = audit["case_id"]
        case_path = CASES_DIR / f"{cid}.json"
        if not case_path.exists():
            failed.append((cid, "case file not found"))
            continue
        case = json.loads(case_path.read_text(encoding="utf-8"))
        new_docstring = splice_logic(case["docstring"], audit["rewritten_docstring"])
        if new_docstring is None:
            failed.append((cid, "could not locate 'Logic:' section in current docstring"))
            continue
        if args.dry_run:
            print(f"=== {cid} ===")
            print(new_docstring)
            print()
        else:
            case["docstring"] = new_docstring
            case_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
        applied.append(cid)

    verb = "Would apply" if args.dry_run else "Applied"
    print(f"{verb} {len(applied)} rewrite(s).")
    if failed:
        print(f"\n{len(failed)} case(s) need manual attention (Logic section not auto-locatable):")
        for cid, reason in failed:
            print(f"  {cid}: {reason}")


if __name__ == "__main__":
    main()
