# ablation_context report

Cases with results: 14 / 14 selected

## Overall
- **total_cases_with_results**: 14
- **generation_failure_rate**: 0.07142857142857142
- **n_scored**: 13
- **paired_flag_accuracy**: 0.15384615384615385
- **pairwise_ranking_accuracy**: 0.3076923076923077
- **roc_auc**: 0.42011834319526625
- **youdens_j_threshold**: (1, 0.0)
- **cohens_kappa_vs_human**: None
- **n_human_reviewed**: 0

## Excluding human-flagged docstring leakage
- **total_cases_with_results**: 9
- **generation_failure_rate**: 0.1111111111111111
- **n_scored**: 8
- **paired_flag_accuracy**: 0.125
- **pairwise_ranking_accuracy**: 0.125
- **roc_auc**: 0.40625
- **youdens_j_threshold**: (1, 0.0)
- **cohens_kappa_vs_human**: None
- **n_human_reviewed**: 0

## Go/no-go
Paired Flag Accuracy = 15.38% -> **NO-GO - rework rubric/prompts before scaling**