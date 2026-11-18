# CSIMS evaluation script

## Purpose

This script evaluates the current CSIMS rule-based Detection Engine against the UNSW-NB15 dataset. It imports the project's existing loader, engine, rules, and configured thresholds. It does not modify the detection rules or configuration.

The evaluation has three levels:

1. **Overall binary evaluation** — all five configured rules together, compared with `Label` (0 = Normal, 1 = Attack). Each source record is counted once, even when several rules match it.
2. **Individual rule evaluation** — each rule is run independently and compared with the same binary `Label`.
3. **Attack-category analysis** — all rules together are evaluated against each `attack_cat` group. This reports the number of attacks detected, missed, and the detection rate for each dataset category. It does not assume that a particular CSIMS rule maps one-to-one to a dataset attack category.

`Label` and `attack_cat` are never passed to the Detection Engine. They are used only after detection for evaluation. GEN-001 and CON-001 keep the CSIMS incident category `Other suspicious activity`.

## Installation and execution

From the project root, activate the virtual environment and run:

```bash
python evaluation/run_evaluation.py
```

The script expects the dataset files at the paths configured in `dataset/loader.py` and uses the project's installed dependencies. Files in `evaluation/results/` are overwritten on each run.

## Output files

Results are written to `evaluation/results/`:

- `overall_metrics.csv` — overall TP, FP, TN, FN, Precision, Recall, F1-score, FPR, and Accuracy.
- `individual_rule_metrics.csv` — the same metrics for each rule independently.
- `attack_category_analysis.csv` — total, detected, and missed attack records and detection rate for each `attack_cat`, plus an `ALL_ATTACKS` summary row.
- `overall_confusion_matrix.csv` — overall 2×2 confusion matrix.
- `confusion_matrix_<rule-id>.csv` — one confusion matrix per rule.
- `evaluation_summary.txt` — readable report covering all three levels and interpretation notes.

CSV files are written with UTF-8 with BOM (`utf-8-sig`) for compatibility with common spreadsheet applications.

## Metric definitions

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1-score = 2 × TP / (2 × TP + FP + FN)
- False Positive Rate = FP / (FP + TN)
- Accuracy = (TP + TN) / (TP + FP + TN + FN)

If a metric's denominator is zero, the script reports 0. Always interpret metrics together with their confusion-matrix counts.

## Important interpretation

- All five configured rules are enabled for this offline evaluation, regardless of runtime enable/disable toggles. This makes the evaluation cover the complete configured rule set.
- Individual rule metrics are binary attack-vs-normal measurements. They do not claim that a rule identifies a specific `attack_cat` subtype.
- Attack-category detection rates describe coverage of each UNSW-NB15 subtype by the complete rule set. They do not establish a unique rule-to-subtype mapping.
- The script checks source record IDs, feature/label alignment, binary labels, category values, and consistency between overall and category-level counts.
- This run evaluates the current configured thresholds on the dataset. It is not an independent holdout evaluation and does not establish generalisation to unseen traffic. If the thesis makes claims about unseen data, threshold calibration and final testing must use separate data partitions.
