# ablation_baseline report

Cases with results: 14 / 14 selected

## Overall
- **total_cases_with_results**: 14
- **generation_failure_rate**: 0.07142857142857142
- **n_scored**: 13
- **paired_flag_accuracy**: 0.15384615384615385
- **pairwise_ranking_accuracy**: 0.38461538461538464
- **roc_auc**: 0.5473372781065089
- **youdens_j_threshold**: (2, 0.15384615384615397)
- **cohens_kappa_vs_human**: None
- **n_human_reviewed**: 0

## Excluding human-flagged docstring leakage
- **total_cases_with_results**: 9
- **generation_failure_rate**: 0.1111111111111111
- **n_scored**: 8
- **paired_flag_accuracy**: 0.0
- **pairwise_ranking_accuracy**: 0.25
- **roc_auc**: 0.515625
- **youdens_j_threshold**: (7, 0.125)
- **cohens_kappa_vs_human**: None
- **n_human_reviewed**: 0

## Go/no-go
Paired Flag Accuracy = 15.38% -> **NO-GO - rework rubric/prompts before scaling**

**Warning:** leakage-excluded Paired Flag Accuracy (0.00%) diverges substantially from the overall figure (15.38%) - treat this as a no-go signal regardless of the overall number, per the plan's success criteria.