# Model evaluation

**Read this first:** the corpus is authored by the project author/assistant, is synthetic, and is `review_status=UNREVIEWED`. It is *not* real traffic and no independent human has reviewed it.
Nothing below is evidence of real-world performance.

## Target and features
Target: `P(text is an injection / exfiltration attempt)` for a request text or a piece of retrieved content. Advisory only.
Features (`fs-1`): hashed char-wb 3-5-grams (2^15) of the text + a hashed token for content source (`user` / `untrusted_content`).
The tool name is deliberately **not** a feature: with it, the first model learned a shortcut (attacks clustered on `email.send` in the authored corpus) and escalated bland benign requests; this was caught by a lifecycle test, the feature was removed, and the model retrained.
Model: class-balanced logistic regression, Platt calibration on the validation split only. Artifact: JSON (no pickle), SHA-256 pinned in the registry.

## Data and splits
`curated_train_v1`: 251 examples, 29 scenario families (templated variants). `adversarial_eval_v1`: 32 hand-written examples in 32 *different* families (paraphrases and obfuscations designed to evade the regex detector).
Training uses a family-grouped, label-stratified 60/20/20 split (train/val/test) so variants of a template never straddle splits; tests assert no family or text overlaps between train and adversarial-eval and that datasets pass validation (duplicates, labels).
Threshold: lowest threshold with validation FPR <= 2% (a security-use-case choice favouring few false alarms). It was fixed by that rule *before* looking at test results and not tuned afterwards.

## Results (this repository, run on 2026-10-11; seed 1234; 95% bootstrap CIs, 1000 resamples; n is tiny, so intervals are wide)
| Set | Detector | n | Precision | Recall | FPR | PR-AUC | Confusion [[TN,FP],[FN,TP]] | Recall 95% CI |
|---|---|---|---|---|---|---|---|---|
| Held-out family split | ML (thr 0.72) | 41 | n/a (no positives predicted) | 0.00 | 0.00 | 0.91 | [[17,0],[24,0]] | [0.00, 0.00] |
| Held-out family split | Regex baseline | 41 | 1.00 | 0.92 | 0.00 | 0.97 | [[17,0],[2,22]] | [0.79, 1.00] |
| Adversarial eval | ML | 32 | 1.00 | 0.06 | 0.00 | 0.68 | [[16,0],[15,1]] | [0.00, 0.20] |
| Adversarial eval | Regex baseline | 32 | 0.75 | 0.19 | 0.06 | 0.58 | [[15,1],[13,3]] | [0.00, 0.39] |

## Interpretation
- The regex baseline looks excellent on the held-out split only because the authored templates share vocabulary with the regexes. On paraphrased/obfuscated attacks it catches 3 of 16.
- The ML model ranks better than regex on the adversarial set (PR-AUC 0.68 vs 0.58) but, at the conservative gated threshold, catches 1 of 16 and none on the held-out split. **At this data scale the model adds essentially no detection value at its deployed operating point.** It is retained as an auditable, gated advisory pipeline, not as a defence.
- Neither detector is a defence against paraphrased injection. The controls that provide the measured protection are authorization, strict schemas, provenance checks, approvals and fail-closed behaviour (benchmark), which do not depend on detecting the wording.
- Calibration was fit on a very small validation split; treat probabilities as uncalibrated.

## Lifecycle and gates (`ml/registry.py`)
CANDIDATE -> gate -> APPROVED (human reviewer) -> ACTIVE (previous version recorded) -> rollback.
Gate (fixed suites, recomputed from the artifact): FPR <= 5% held-out and <= 10% adversarial; no recall or PR-AUC regression > 0.05 versus the active model. Rejected candidates cannot be approved.
The gate does not set an attack-success threshold for the ML model, because attack success is determined by the deterministic controls, not the model. Runtime never changes a model; a missing, corrupt, stale, or incompatible model makes protected calls escalate.

## What would make this meaningful
Real, independently reviewed labelled traffic; data from the target agents/tools; hundreds of examples per family; threshold selection by cross-validation on that data; periodic re-evaluation as attackers adapt.
