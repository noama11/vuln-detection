"""Read-only loaders shared by every arm under experiments/.

Nothing in this package writes to cases/, results/, reports/ or scripts/. Arms
write only inside their own experiments/<arm>/ directory. See the isolation rule
in the plan: the published qwen_full and Claude arms must stay byte-reproducible.

The central abstraction is `Pair`: one case reduced to the two judge verdicts
that the paired metrics operate on, plus the fields the clustered resampling
needs (cve_id, repo). Every metric in metrics.py consumes a list of Pair.
"""
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CASES_DIR = ROOT / "cases"
RESULTS_DIR = ROOT / "results"

SECURITY = "security_vulnerability_concern"
DEGENERATE = "degenerate_generation"

# Reuse the published implementations rather than writing a second, subtly
# different copy - importing is read-only, and it guarantees any number we
# report is computed the same way reports/qwen_full_report.md computed it.
sys.path.insert(0, str(ROOT / "scripts"))
from compute_metrics import auc_from_scores, cohens_kappa, youdens_j  # noqa: E402,F401


@dataclass(frozen=True)
class Pair:
    """One case: the vulnerable-side and fixed-side judge verdicts side by side.

    `flag_v` / `flag_f` are the security_vulnerability_concern decisions that
    Paired Flag Accuracy is defined over; `score_v` / `score_f` feed 2AFC and
    ROC-AUC. `degenerate` cases are carried rather than dropped at load time so
    each metric can decide for itself - compute_metrics.py excludes them from
    n_scored, and we must reproduce that exactly before diverging from it.
    """
    case_id: str
    cve_id: str
    repo: str
    language: str
    score_v: int
    score_f: int
    cat_v: str
    cat_f: str
    degenerate: bool

    @property
    def flag_v(self):
        return self.cat_v == SECURITY

    @property
    def flag_f(self):
        return self.cat_f == SECURITY

    @property
    def paired_flag_correct(self):
        return self.flag_v and not self.flag_f


def load_cases(cases_dir=None, ok_only=True):
    """case_id -> case dict. `ok_only` applies the same extraction filter that
    compute_metrics.py:102 and run_cases_local.py:329 both apply."""
    d = Path(cases_dir) if cases_dir else CASES_DIR
    out = {}
    for fp in sorted(d.glob("*.json")):
        c = json.loads(fp.read_text(encoding="utf-8"))
        if ok_only and c.get("extraction_status") != "ok":
            continue
        out[c["case_id"]] = c
    return out


def load_records(results_dir):
    """case_id -> result record, from any directory using the standard result
    schema (results/qwen_full/ or an arm's own results/)."""
    d = Path(results_dir)
    if not d.is_absolute():
        d = ROOT / d
    out = {}
    for fp in sorted(d.glob("*.json")):
        if fp.name in ("pilot_review.csv",):
            continue
        r = json.loads(fp.read_text(encoding="utf-8"))
        if "case_id" in r and "judge_vs_vulnerable" in r:
            out[r["case_id"]] = r
    return out


def to_pairs(records):
    """Result records -> Pair list, preserving degenerate cases."""
    pairs = []
    for r in records.values():
        jv, jf = r["judge_vs_vulnerable"], r["judge_vs_fixed"]
        pairs.append(Pair(
            case_id=r["case_id"],
            cve_id=r.get("cve_id") or "",
            repo=r.get("repo") or "",
            language=r.get("language") or "",
            score_v=int(jv["score"]),
            score_f=int(jf["score"]),
            cat_v=jv["category"],
            cat_f=jf["category"],
            degenerate=(jv["category"] == DEGENERATE or jf["category"] == DEGENERATE),
        ))
    return sorted(pairs, key=lambda p: p.case_id)


def scored(pairs):
    """The non-degenerate subset - the denominator compute_metrics.py calls
    n_scored (357 of 391 for qwen_full)."""
    return [p for p in pairs if not p.degenerate]


# --------------------------------------------------------------------------- #
# corpus-level helpers used by the provenance and sufficiency analyses
# --------------------------------------------------------------------------- #

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")

# Language keywords and pervasive idioms carry no provenance information: they
# appear in essentially every C function on both sides, so leaving them in would
# dilute the vulnerable-vs-fixed asymmetry we are trying to measure.
STOPWORDS = set("""
if else for while return int char void const struct static unsigned long size len
null goto err error ret buf sizeof break continue case switch do default enum
union typedef extern inline signed short float double bool true false
the of to and is a an in on it this that be with from as or not are was were
""".split())


def identifiers(text):
    return {t.lower() for t in _IDENT.findall(text or "")} - STOPWORDS


def provenance_counts(case):
    """(vulnerable-only hits, fixed-only hits) - how many identifiers unique to
    each side of the fix the docstring mentions.

    A spec written from the vulnerable code mentions vulnerable-only names it
    should not know about; a spec written from the fixed code does the mirror.
    The corpus-wide ratio of these two totals is the provenance signal.
    """
    v = identifiers(case["vulnerable_snippet"])
    f = identifiers(case["fixed_snippet"])
    d = identifiers(case["docstring"])
    return len((v - f) & d), len((f - v) & d)
