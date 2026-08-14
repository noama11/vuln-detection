"""Paired metrics with the statistical machinery the published report lacks.

Three corrections over scripts/compute_metrics.py, which stays untouched:

1. **Clustered CIs.** The 357 scored cases span only 302 CVEs and 66 repos, half
   of them torvalds/linux. Binomial CIs assume case-level independence the
   corpus does not have; we resample whole CVEs instead.
2. **Tie-corrected 2AFC.** compute_metrics.py:239 counts `score_f > score_v`,
   so a tie scores as a failure. 43% of cases tie, which is why the published
   26.3% is not comparable to a 50% chance line.
3. **A permutation null.** The report's independence baseline (0.412 x 0.560 =
   23.1%) *assumes* the two judge calls are independent in order to argue they
   are not. Swapping the two verdicts within a case is exchangeable under the
   null that the reference does not matter, so it tests the same claim without
   assuming it.
"""
import math
import random
from collections import Counter, defaultdict

from data import Pair, auc_from_scores, scored


# --------------------------------------------------------------------------- #
# point estimates
# --------------------------------------------------------------------------- #

def pfa(pairs):
    """Paired Flag Accuracy - the pre-registered primary metric."""
    s = scored(pairs)
    return (sum(p.paired_flag_correct for p in s) / len(s)) if s else None


def afc(pairs):
    """Two-alternative forced choice on the judge score.

    Returns raw (ties counted as failures, matching the published figure),
    tie-corrected (ties excluded, the figure comparable to a 50% chance line),
    and the tie rate that separates them.
    """
    s = scored(pairs)
    if not s:
        return {"raw": None, "tie_corrected": None, "tie_rate": None, "n_untied": 0}
    gt = sum(1 for p in s if p.score_f > p.score_v)
    lt = sum(1 for p in s if p.score_f < p.score_v)
    ties = len(s) - gt - lt
    return {
        "raw": gt / len(s),
        "tie_corrected": (gt / (gt + lt)) if (gt + lt) else None,
        "tie_rate": ties / len(s),
        "n_untied": gt + lt,
    }


def auc(pairs):
    """Pooled Mann-Whitney AUC, fixed-side scores vs vulnerable-side scores."""
    s = scored(pairs)
    if not s:
        return None
    return auc_from_scores([p.score_f for p in s], [p.score_v for p in s])


def flag_rates(pairs):
    s = scored(pairs)
    if not s:
        return {"vulnerable": None, "fixed": None, "independence_baseline": None}
    fv = sum(p.flag_v for p in s) / len(s)
    ff = sum(p.flag_f for p in s) / len(s)
    return {
        "vulnerable": fv,
        "fixed": ff,
        # What PFA two *independent* judgments with these marginals would yield.
        "independence_baseline": fv * (1 - ff),
    }


def outcome_distribution(pairs):
    """The four judge-verdict combinations - the shape PFA alone hides."""
    s = scored(pairs)
    out = Counter()
    for p in s:
        if p.flag_v and not p.flag_f:
            out["vulnerable only (method working)"] += 1
        elif p.flag_f and not p.flag_v:
            out["fixed only (exactly backwards)"] += 1
        elif p.flag_v and p.flag_f:
            out["both (cannot discriminate)"] += 1
        else:
            out["neither (misses the CVE)"] += 1
    return out, len(s)


def mean_scores(pairs):
    s = scored(pairs)
    if not s:
        return {}
    mv = sum(p.score_v for p in s) / len(s)
    mf = sum(p.score_f for p in s) / len(s)
    return {"vulnerable": mv, "fixed": mf, "delta_fixed_minus_vulnerable": mf - mv}


# --------------------------------------------------------------------------- #
# score/category dependence
# --------------------------------------------------------------------------- #

def score_category_mi(pairs):
    """Mutual information between the judge's score and its category, in bits,
    pooled over both judge calls.

    The rubric binds score ranges to categories (equivalent -> 8-10, security
    -> 1-5, ...), so if I(score;category) is close to H(score) the score is a
    relabelling of the category and ROC-AUC is not evidence independent of PFA.
    """
    joint = Counter()
    for p in pairs:
        joint[(p.score_v, p.cat_v)] += 1
        joint[(p.score_f, p.cat_f)] += 1
    n = sum(joint.values())
    if not n:
        return None
    ps, pc = Counter(), Counter()
    for (s, c), k in joint.items():
        ps[s] += k
        pc[c] += k
    mi = 0.0
    for (s, c), k in joint.items():
        pxy = k / n
        mi += pxy * math.log2(pxy / ((ps[s] / n) * (pc[c] / n)))
    h_score = -sum((v / n) * math.log2(v / n) for v in ps.values())
    return {
        "mi_bits": mi,
        "entropy_score_bits": h_score,
        "fraction_of_score_entropy_explained": (mi / h_score) if h_score else None,
        "distinct_scores_used": len(ps),
        "score_histogram": dict(sorted(ps.items())),
    }


# --------------------------------------------------------------------------- #
# resampling
# --------------------------------------------------------------------------- #

def cluster_bootstrap(pairs, stat, by="cve_id", n_boot=10000, seed=1234, alpha=0.05):
    """Percentile CI from resampling whole clusters with replacement.

    Cases sharing a CVE are not independent draws - a multi-function commit
    contributes several cases whose outcomes rise and fall together - so the
    resampling unit is the cluster, not the case.
    """
    groups = defaultdict(list)
    for p in pairs:
        groups[getattr(p, by) or p.case_id].append(p)
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
    lo = vals[int(alpha / 2 * len(vals))]
    hi = vals[min(len(vals) - 1, int((1 - alpha / 2) * len(vals)))]
    return {"lo": lo, "hi": hi, "n_clusters": len(keys), "n_boot": len(vals)}


def permutation_test(pairs, stat=pfa, n_perm=10000, seed=1234):
    """Exchangeability test: within each case, swap the two judge verdicts with
    probability 1/2 and recompute the statistic.

    Under the null that the reference shown does not influence the verdict, the
    two calls are exchangeable, so the observed statistic should sit inside this
    distribution. A one-sided p is reported; a *low* observed value relative to
    the null (as expected here) shows up as a p near 1, which is itself the
    finding - the detector is anti-correlated with the label.
    """
    observed = stat(pairs)
    rng = random.Random(seed)
    null = []
    for _ in range(n_perm):
        perm = []
        for p in pairs:
            if rng.random() < 0.5:
                perm.append(Pair(
                    case_id=p.case_id, cve_id=p.cve_id, repo=p.repo,
                    language=p.language,
                    score_v=p.score_f, score_f=p.score_v,
                    cat_v=p.cat_f, cat_f=p.cat_v,
                    degenerate=p.degenerate,
                ))
            else:
                perm.append(p)
        v = stat(perm)
        if v is not None:
            null.append(v)
    null.sort()
    n = len(null)
    ge = sum(1 for v in null if v >= observed)
    le = sum(1 for v in null if v <= observed)
    return {
        "observed": observed,
        "null_mean": sum(null) / n if n else None,
        "null_lo95": null[int(0.025 * n)] if n else None,
        "null_hi95": null[min(n - 1, int(0.975 * n))] if n else None,
        # +1 corrections: an empirical p from n_perm draws can never be 0.
        "p_greater": (ge + 1) / (n + 1),
        "p_less": (le + 1) / (n + 1),
        "n_perm": n,
    }


# --------------------------------------------------------------------------- #

def summary(pairs):
    """Every headline number for one arm, in one dict."""
    dist, n_scored = outcome_distribution(pairs)
    degen = [p for p in pairs if p.degenerate]
    return {
        "n_cases": len(pairs),
        "n_scored": n_scored,
        "n_degenerate": len(degen),
        "degenerate_rate": len(degen) / len(pairs) if pairs else None,
        "pfa": pfa(pairs),
        "afc": afc(pairs),
        "roc_auc": auc(pairs),
        "flag_rates": flag_rates(pairs),
        "mean_scores": mean_scores(pairs),
        "outcome_distribution": dict(dist),
    }
