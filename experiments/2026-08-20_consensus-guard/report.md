# Improving the method — results

Same corpus, same model, same generator prompt. The premise is intact throughout: the Generator sees only `{language, docstring}`, the Judge sees one reference at a time and is never told which, and no supervised labels enter the detector.

**Primary metric is directional accuracy**: given the same candidate(s), does the vulnerable reference score higher than the fixed one? Chance is exactly 50% on the decided subset. Ties are reported as coverage, never counted as either successes or failures. This replaces Paired Flag Accuracy, whose chance level is 25% and which requires one specific category out of five (see `experiments/FINDINGS.md`).

| Arm | n | decided | coverage | accuracy | 95% CI | p (vs 50%) |
|---|---|---|---|---|---|---|
| published method (5-way taxonomy) | 391 | 230 | 58.8% | **43.5%** | [36.9%, 50.0%] | 0.0556 |
| guard contrast, K=1 | 391 | 170 | 43.5% | **48.8%** | [41.4%, 56.1%] | 0.8181 |
| consensus guard, K=5 | 391 | 175 | 44.8% | **50.3%** | [42.7%, 57.7%] | 1.0000 |

`*` p<0.05  `**` p<0.01  `***` p<0.001, exact two-sided binomial against 50%. CIs are CVE-clustered bootstraps (10k resamples).

## The two pre-registered tests

Both were fixed in `PRE_REGISTRATION.md` before these records existed. Two tests, so the Bonferroni-corrected threshold is p < 0.025.

| # | hypothesis | decided | coverage | accuracy | 95% CI | p |
|---|---|---|---|---|---|---|
| H1 primary | consensus exposure of the target | 175 | 44.8% | **50.3%** | [42.7%, 57.7%] | 1.0000 (n.s.) |
| H2 secondary | net exposure (target - consensus control) | 244 | 62.4% | **49.6%** | [43.1%, 56.1%] | 0.9490 (n.s.) |

And the pre-registered stratified prediction (the dissociation), on H1:

| stratum | decided | accuracy | 95% CI | p |
|---|---|---|---|---|
| anticipatable defensive step | 93 | 55.9% | [45.9%, 65.9%] | 0.2997 |
| domain-specific / other | 82 | 43.9% | [33.3%, 54.9%] | 0.3203 |


## Where it works: stratified by what the fix does

The method's hypothesis is that an independent implementation written from the specification contains a defensive step the vulnerable version omits. That is only possible when the omitted step is one such an author could plausibly write — a bounds check, a null check, an initialisation. It cannot work when the fix is a domain-specific correction no reader of the spec could anticipate. The split is lexical, computed from the diff with no model involved (`experiments/common/cve_taxonomy.py`), so it cannot be contaminated by the model being evaluated.

**published method (5-way taxonomy)**

| stratum | n | decided | accuracy | 95% CI | p |
|---|---|---|---|---|---|
| fix adds an anticipatable defensive step | 195 | 117 | 60.0% | **43.6%** | [35.0%, 52.1%] | 0.1953 |
| fix is domain-specific / other | 196 | 113 | 57.7% | **43.4%** | [33.0%, 53.8%] | 0.1876 |

**guard contrast, K=1**

| stratum | n | decided | accuracy | 95% CI | p |
|---|---|---|---|---|---|
| fix adds an anticipatable defensive step | 195 | 86 | 44.1% | **54.7%** | [44.1%, 65.1%] | 0.4505 |
| fix is domain-specific / other | 196 | 84 | 42.9% | **42.9%** | [32.5%, 53.7%] | 0.2299 |

**consensus guard, K=5**

| stratum | n | decided | accuracy | 95% CI | p |
|---|---|---|---|---|---|
| fix adds an anticipatable defensive step | 195 | 93 | 47.7% | **55.9%** | [45.9%, 65.9%] | 0.2997 |
| fix is domain-specific / other | 196 | 82 | 41.8% | **43.9%** | [33.3%, 54.9%] | 0.3203 |

By fix category (**consensus guard, K=5**):

| fix category | n | decided | accuracy |
|---|---|---|---|
| other_modification | 129 | 54 | 38.9% |
| adds_bounds_or_range_check | 122 | 62 | 59.7% |
| adds_other_conditional | 43 | 18 | 50.0% |
| initialisation_or_clearing | 40 | 14 | 50.0% |
| adds_null_or_error_check | 33 | 17 | 47.1% |
| lifetime_free_or_lock | 13 | 4 | 50.0% |
| type_or_cast_change | 11 | 6 | 66.7% |

## Coverage–accuracy trade-off

Abstention is legitimate for a triage tool: a detector that is reliable on the cases it is confident about is useful even if it is at chance overall. Each row demands a larger gap between the two sides before the detector will answer.

**consensus guard, K=5**

| required score margin | cases answered | coverage | accuracy | p |
|---|---|---|---|---|
| >= 1 | 175 | 44.8% | 50.3% | 1.0000 |
| >= 2 | 150 | 38.4% | 52.0% | 0.6832 |
| >= 3 | 77 | 19.7% | 50.6% | 1.0000 |
| >= 4 | 63 | 16.1% | 50.8% | 1.0000 |
| >= 5 | 17 | 4.3% | 47.1% | 1.0000 |
| >= 6 | 16 | 4.1% | 50.0% | 1.0000 |

