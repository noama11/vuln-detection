"""Paired evaluation for a detector that emits a continuous per-version score.

The primary metric is **directional accuracy**: given the same reconstructions,
does the vulnerable version score higher than the patched one? Chance is exactly
50% on the decided (untied) subset, with no class-imbalance correction to argue
about, because every case carries exactly one version of each kind by
construction. Ties are reported as coverage, never folded into the numerator or
silently dropped - scoring them either way would let the analyst choose the
headline.

Because abstention is legitimate for a triage tool, the headline is a
**coverage-accuracy curve**: sweeping a margin threshold trades how many cases
the detector will answer on against how often it is right. A detector that is
85% accurate on the 20% of cases it is most confident about is useful even if it
is at chance overall.
"""
import math
import random
from collections import defaultdict


def directional(records, score_fn):
    """(n_correct, n_wrong, n_tied) over paired records."""
    c = w = t = 0
    for r in records:
        a, b = score_fn(r["judge_vs_vulnerable"]), score_fn(r["judge_vs_fixed"])
        if a > b:
            c += 1
        elif a < b:
            w += 1
        else:
            t += 1
    return c, w, t


def accuracy(records, score_fn):
    c, w, _ = directional(records, score_fn)
    return (c / (c + w)) if (c + w) else None


def binom_two_sided(k, n, p=0.5):
    """Exact two-sided binomial p-value, for accuracy against a 50% chance line."""
    if n == 0:
        return None

    def pmf(i):
        return math.comb(n, i) * p ** i * (1 - p) ** (n - i)

    obs = pmf(k)
    return min(1.0, sum(pmf(i) for i in range(n + 1) if pmf(i) <= obs * (1 + 1e-12)))


def cluster_bootstrap(records, stat, key=lambda r: r.get("cve_id") or r["case_id"],
                      n_boot=10000, seed=1234, alpha=0.05):
    """Percentile CI resampling whole CVE clusters, not cases."""
    groups = defaultdict(list)
    for r in records:
        groups[key(r)].append(r)
    keys = list(groups)
    rng = random.Random(seed)
    vals = []
    for _ in range(n_boot):
        sample = []
        for _ in range(len(keys)):
            sample.extend(groups[keys[rng.randrange(len(keys))]])
        v = stat(sample)
        if v is not None:
            vals.append(v)
    if not vals:
        return None
    vals.sort()
    return (vals[int(alpha / 2 * len(vals))],
            vals[min(len(vals) - 1, int((1 - alpha / 2) * len(vals)))])


def auc(records, score_fn):
    """P(vulnerable scores above fixed), ties counted as half - the standard
    Mann-Whitney convention, so 0.5 is exactly chance."""
    c, w, t = directional(records, score_fn)
    n = c + w + t
    return ((c + 0.5 * t) / n) if n else None


def coverage_curve(records, score_fn, margins=(1, 2, 3, 4, 5)):
    """Accuracy as a function of how large a score gap the detector demands.

    Each row answers: if the detector only reports a case when the two sides
    differ by at least `margin`, how often is it right, and on what fraction of
    the corpus does it speak at all?
    """
    rows = []
    n = len(records)
    for m in margins:
        c = w = 0
        for r in records:
            a, b = score_fn(r["judge_vs_vulnerable"]), score_fn(r["judge_vs_fixed"])
            if abs(a - b) < m:
                continue
            if a > b:
                c += 1
            else:
                w += 1
        d = c + w
        rows.append({"margin": m, "n_decided": d, "coverage": d / n if n else 0,
                     "accuracy": (c / d) if d else None,
                     "p": binom_two_sided(c, d) if d else None})
    return rows


def summarise(records, score_fn, label=""):
    c, w, t = directional(records, score_fn)
    d = c + w
    return {
        "label": label,
        "n": len(records),
        "n_decided": d,
        "coverage": d / len(records) if records else None,
        "tie_rate": t / len(records) if records else None,
        "accuracy": (c / d) if d else None,
        "ci": cluster_bootstrap(records, lambda rs: accuracy(rs, score_fn)),
        "p_value": binom_two_sided(c, d) if d else None,
        "auc": auc(records, score_fn),
        "n_correct": c,
        "n_wrong": w,
    }
