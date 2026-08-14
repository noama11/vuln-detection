"""Classify each case by *what the fix actually does* to the code.

The method's hypothesis is that an implementation written from the spec will
contain a defensive step the vulnerable version omits. That can only work when
the missing step is one an independent author would plausibly include — a null
check, a bounds check, an initialisation. It cannot work when the fix is a
domain-specific correction no reader of the specification could anticipate
(reordering two locks, changing a magic constant, fixing a protocol detail).

So the interesting question is not "does the method work?" but "on which kinds of
fix does it work?". This module supplies that stratification lexically, from the
diff alone, with no model involved and no labels.

Deliberately lexical and auditable rather than LLM-assigned: the strata are used
to make a positive claim, so they must not depend on the same model being
evaluated.
"""
import difflib
import re

# Order matters: the first pattern that matches wins, most specific first.
CATEGORIES = [
    ("adds_bounds_or_range_check", re.compile(
        r"\b(if|while)\b[^\n]*("
        r"[<>]=?|\bmin\b|\bmax\b|\bMIN\b|\bMAX\b|\bsize\b|\blen\b|\blength\b|"
        r"\bcount\b|\bnr_\w+|\blimit\b|\bbound\w*|\boverflow\b|\bcapacity\b)",
        re.IGNORECASE)),
    ("adds_null_or_error_check", re.compile(
        r"\b(if|while)\b[^\n]*(!\s*\w|==\s*NULL|!=\s*NULL|\bIS_ERR\b|\bERR_PTR\b|"
        r"<\s*0|==\s*0|\bnullptr\b|\bNULL\b)", re.IGNORECASE)),
    ("adds_other_conditional", re.compile(r"\b(if|BUG_ON|WARN_ON|assert|ASSERT)\b")),
    ("initialisation_or_clearing", re.compile(
        r"(=\s*NULL|=\s*0\b|\bmemset\b|\bcalloc\b|\bzalloc\b|\bkzalloc\b|"
        r"\bbzero\b|\binit\w*\()", re.IGNORECASE)),
    ("lifetime_free_or_lock", re.compile(
        r"\b(free|kfree|vfree|release|put|unlock|lock|mutex|spin_|refcount|"
        r"get_|ref\b|destroy|close|dispose)\w*\b", re.IGNORECASE)),
    ("type_or_cast_change", re.compile(
        r"\b(unsigned|signed|size_t|ssize_t|int64|uint|u8|u16|u32|u64|s8|s16|"
        r"s32|s64|long long|\(\s*\w+\s*\*?\s*\))\b")),
]


def changed_lines(case):
    """(added_lines, removed_lines) between the two versions."""
    v = (case["vulnerable_snippet"] or "").splitlines()
    f = (case["fixed_snippet"] or "").splitlines()
    d = list(difflib.unified_diff(v, f, lineterm="", n=0))
    add = [l[1:] for l in d if l.startswith("+") and not l.startswith("+++")]
    rem = [l[1:] for l in d if l.startswith("-") and not l.startswith("---")]
    return add, rem


def classify(case):
    """What kind of change the fix makes. One label per case."""
    add, rem = changed_lines(case)
    added = "\n".join(add)
    if not add and not rem:
        return "no_diff"
    # Only lines the fix ADDS can represent a step the vulnerable version lacks.
    for name, pat in CATEGORIES:
        if pat.search(added):
            return name
    if add and not rem:
        return "pure_addition_other"
    return "other_modification"


# Fixes whose added lines introduce a defensive step an independent author,
# working from the specification alone, could plausibly also have written. These
# are the cases where the method's hypothesis is even in principle testable.
ANTICIPATABLE = {
    "adds_bounds_or_range_check",
    "adds_null_or_error_check",
    "initialisation_or_clearing",
}


def is_anticipatable(case):
    return classify(case) in ANTICIPATABLE


def fix_size(case):
    add, rem = changed_lines(case)
    return len(add) + len(rem)
