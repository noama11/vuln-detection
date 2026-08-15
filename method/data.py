"""Read-only loaders for the corpus and for result records.

Nothing here writes. `run.py` writes only under `method/candidates/` and
`method/results/<run>/`; `report.py` writes only its own report file. The
corpus in `cases/` is treated as immutable input - it is content-addressed by
`scripts/corpus_sha.py` and gated by `scripts/validate_corpus.py`, and any
figure produced against a modified corpus would carry a digest that no longer
matches the one recorded in the result files.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = ROOT / "cases"


def load_cases(cases_dir=None, ok_only=True):
    """case_id -> case dict.

    `ok_only` drops the records the extractor could not pose as a
    reconstruction task (patched line at file scope, macros with
    statement-expression bodies, functions renamed by the patch). Those are
    carried in the corpus with an `extraction_status` explaining why rather
    than deleted, so the exclusion is auditable; 626 of the 792 records are
    `ok`.
    """
    d = Path(cases_dir) if cases_dir else CASES_DIR
    out = {}
    for fp in sorted(d.glob("*.json")):
        c = json.loads(fp.read_text(encoding="utf-8"))
        if ok_only and c.get("extraction_status") != "ok":
            continue
        out[c["case_id"]] = c
    return out


def load_records(results_dir):
    """case_id -> result record, from a directory written by `run.py --stage judge`."""
    d = Path(results_dir)
    if not d.is_absolute():
        d = ROOT / d
    out = {}
    for fp in sorted(d.glob("*.json")):
        r = json.loads(fp.read_text(encoding="utf-8"))
        if "case_id" in r and "judge_vs_vulnerable" in r:
            out[r["case_id"]] = r
    return out
