"""Content-address a case corpus, the way agent_prompts.py content-addresses
the rubric.

Every result record already carries `prompt_sha`, so a number can always be
traced back to the exact prompt that produced it. There was no equivalent for
the corpus: swapping `cases/` changed every downstream figure with no trace in
any artifact. That is what made the extraction defect expensive to find - the
eight published arms cannot say which corpus they ran against, only that it was
"whatever cases/ held at the time".

`corpus_sha` hashes the fields that determine what the model sees - case_id,
docstring, and both snippets - over the cases a run would actually select
(`extraction_status == "ok"`), in sorted order. It deliberately ignores
metadata that does not reach the model (cve_summary, commit_message, line
ranges, extraction bookkeeping), so cosmetic re-extractions that leave the
inputs identical produce the same sha.

    python3 scripts/corpus_sha.py                     # the published cases/
    python3 scripts/corpus_sha.py --cases-dir <dir>
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CASES = ROOT / "cases"

# The fields that reach the generator or the judge. Changing any of them changes
# what was measured; changing anything else does not.
MATERIAL_FIELDS = ("case_id", "docstring", "vulnerable_snippet", "fixed_snippet")


def corpus_sha(cases_dir=None, length=12):
    """Short hex digest over the material content of the selectable cases."""
    d = Path(cases_dir) if cases_dir else DEFAULT_CASES
    h = hashlib.sha256()
    n = 0
    for fp in sorted(d.glob("*.json")):
        c = json.loads(fp.read_text(encoding="utf-8"))
        if c.get("extraction_status") != "ok":
            continue
        n += 1
        for field in MATERIAL_FIELDS:
            h.update(b"\x00")
            h.update((c.get(field) or "").encode("utf-8"))
    return h.hexdigest()[:length], n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases-dir", default=str(DEFAULT_CASES))
    ap.add_argument("--length", type=int, default=12)
    args = ap.parse_args()
    sha, n = corpus_sha(args.cases_dir, args.length)
    d = Path(args.cases_dir)
    rel = d.relative_to(ROOT) if d.is_relative_to(ROOT) else d
    print(f"corpus:     {rel}")
    print(f"ok cases:   {n}")
    print(f"corpus_sha: {sha}")


if __name__ == "__main__":
    main()
