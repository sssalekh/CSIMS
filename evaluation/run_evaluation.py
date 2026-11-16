"""Evaluate the CSIMS rule-based Detection Engine against UNSW-NB15.

Run from the project root:
    python evaluation/run_evaluation.py

The Detection Engine receives feature columns only. Ground-truth fields are
kept separate and are read only after detection for evaluation.
"""
from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dataset.loader import iter_dataset_batches  # noqa: E402
from detection.config import DETECTION_THRESHOLDS  # noqa: E402
from detection.engine import DetectionEngine  # noqa: E402
from detection.rules import build_detection_rules  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"
BATCH_SIZE = 10_000


def _empty_counts() -> dict[str, int]:
    return {"TP": 0, "FP": 0, "TN": 0, "FN": 0}


def _update_counts(counts: dict[str, int], actual: pd.Series,
            predicted: pd.Series) -> None:
    if not actual.index.equals(predicted.index):
        raise ValueError("Actual labels and predictions are not index-aligned.")
    a = actual.to_numpy(dtype="int8")
    p = predicted.to_numpy(dtype="int8")
    counts["TP"] += int(((a == 1) & (p == 1)).sum())
    counts["FP"] += int(((a == 0) & (p == 1)).sum())
    counts["TN"] += int(((a == 0) & (p == 0)).sum())
    counts["FN"] += int(((a == 1) & (p == 0)).sum())


def _calculate_metrics(counts: dict[str, int]) -> dict[str, int | float]:
    tp, fp, tn, fn = (counts[k] for k in ("TP", "FP", "TN", "FN"))
    total = tp + fp + tn + fn
    return {
        **counts,
        "total_records": total,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "f1_score": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "accuracy": (tp + tn) / total if total else 0.0,
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError(f"Refusing to write an empty results file: {path.name}")
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _write_confusion_matrix(path: Path, counts: dict[str, int]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["Actual / Predicted", "Predicted Normal", "Predicted Attack"])
        writer.writerow(["Actual Normal", counts["TN"], counts["FP"]])
        writer.writerow(["Actual Attack", counts["FN"], counts["TP"]])


def _percent(value: float) -> str:
    return f"{value * 100:.2f}%"


def _detected_series(index: pd.Index, detections: pd.DataFrame,
                context: str) -> pd.Series:
    """Convert engine output to one binary prediction per source record."""
    predicted = pd.Series(0, index=index, dtype="int8")
    if detections.empty:
        return predicted
    if "source_record_id" not in detections.columns:
        raise ValueError(f"{context}: engine output has no source_record_id column.")
    ids = detections["source_record_id"]
    if ids.isna().any() or ids.duplicated().any():
        raise ValueError(f"{context}: duplicate or null source record IDs in detections.")
    unknown = ~ids.isin(index)
    if unknown.any():
        sample = ids[unknown].head(5).tolist()
        raise ValueError(f"{context}: detections contain IDs outside this batch: {sample}")
    predicted.loc[ids.tolist()] = 1
    return predicted


def _validate_batch(batch: Any, expected_start: int) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series]:
    features = batch.features
    ground_truth = batch.ground_truth
    if not features.index.equals(ground_truth.index):
        raise ValueError("Feature and ground-truth indexes do not match.")
    if not features.index.is_unique:
        raise ValueError("Feature indexes must be unique within each batch.")
    if batch.start_record_id != expected_start:
        raise ValueError(
            f"Dataset batches are not contiguous: expected start ID {expected_start}, "
            f"received {batch.start_record_id}."
        )
    if len(features) != batch.total_records:
        raise ValueError("Batch metadata total_records does not match its actual row count.")
    expected_index = pd.RangeIndex(batch.start_record_id, batch.end_record_id + 1)
    if not features.index.equals(expected_index):
        raise ValueError("Source record IDs do not match the batch's declared range.")
    for column in ("Label", "attack_cat"):
        if column not in ground_truth.columns:
            raise ValueError(f"Ground-truth data does not contain '{column}'.")
    labels = pd.to_numeric(ground_truth["Label"], errors="raise")
    if labels.isna().any() or not labels.isin([0, 1]).all():
        raise ValueError("Label must contain only non-null binary values 0 and 1.")
    labels = labels.astype("int8")
    categories = ground_truth["attack_cat"].astype("string").str.strip()
    invalid_attack_categories = (labels == 1) & (categories.isna() | categories.eq(""))
    if invalid_attack_categories.any():
        raise ValueError("One or more attack records have an empty attack_cat value.")
    return features, ground_truth, labels


def _write_report(path: Path, overall: dict, individual_rows: list[dict],
            category_rows: list[dict], records: int) -> None:
    lines = [
        "CSIMS Detection Evaluation", "=========================", "",
        "Dataset: UNSW-NB15", f"Records evaluated: {records:,}",
        "Detection input: feature columns only.",
        "Ground truth: Label (0 = Normal, 1 = Attack).",
        "attack_cat is used only after detection for attack-category analysis.",
        "All five configured rules are included in this offline evaluation,",
        "regardless of runtime enable/disable toggles.", "",
        "LEVEL 1 — OVERALL BINARY EVALUATION", "------------------------------------",
        f"TP: {overall['TP']:,}", f"FP: {overall['FP']:,}",
        f"TN: {overall['TN']:,}", f"FN: {overall['FN']:,}",
        f"Precision: {_percent(overall['precision'])}",
        f"Recall: {_percent(overall['recall'])}",
        f"F1-score: {_percent(overall['f1_score'])}",
        f"False Positive Rate: {_percent(overall['false_positive_rate'])}",
        f"Accuracy: {_percent(overall['accuracy'])}", "",
        "LEVEL 2 — INDIVIDUAL RULE EVALUATION", "-------------------------------------",
        "Each rule is evaluated independently against binary Label.", "",
    ]
    for row in individual_rows:
        lines.extend([
            f"{row['rule_id']} — {row['rule_name']}",
            f"  TP={row['TP']:,}, FP={row['FP']:,}, TN={row['TN']:,}, FN={row['FN']:,}",
            f"  Precision={_percent(row['precision'])}; Recall={_percent(row['recall'])}; "
            f"F1={_percent(row['f1_score'])}; FPR={_percent(row['false_positive_rate'])}", "",
        ])
    lines.extend([
        "LEVEL 3 — ATTACK-CATEGORY ANALYSIS", "-----------------------------------",
        "All rules are considered together. Detection rate is calculated within",
        "each UNSW-NB15 attack_cat group. No one-to-one mapping between a CSIMS",
        "rule and an UNSW-NB15 attack category is assumed.", "",
    ])
    for row in category_rows:
        lines.append(
            f"{row['attack_category']}: {row['detected_attack_records']:,}/"
            f"{row['total_attack_records']:,} detected "
            f"({_percent(row['detection_rate'])}); "
            f"{row['missed_attack_records']:,} missed"
        )
    lines.extend([
        "", "INTERPRETATION NOTES", "--------------------",
        "- Overall predictions count each source record once, even if several rules match.",
        "- Individual rule results are one-vs-rest binary metrics, not attack-subtype accuracy.",
        "- attack_cat analysis describes coverage by dataset subtype; it does not establish",
        "  that a particular CSIMS rule uniquely detects that subtype.",
        "- GEN-001 and CON-001 retain the CSIMS category 'Other suspicious activity'.",
        "- These results evaluate the current configured thresholds on this dataset; they are",
        "  not an independent holdout estimate of performance on unseen traffic.",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def run_evaluation(batch_size: int = BATCH_SIZE) -> None:
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size <= 0:
        raise ValueError("Batch size must be a positive integer.")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rules = build_detection_rules(DETECTION_THRESHOLDS)
    # This is an offline evaluation of the complete five-rule set, not the
    # application's current runtime toggle state.
    for rule in rules:
        rule.enabled = True

    overall_engine = DetectionEngine(rules)
    individual_engines = {rule.rule_id: DetectionEngine([rule]) for rule in rules}
    overall_counts = _empty_counts()
    individual_counts = {rule.rule_id: _empty_counts() for rule in rules}
    category_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total_attack_records": 0, "detected_attack_records": 0}
    )

    total_records = 0
    expected_start = 0
    print("Starting CSIMS evaluation...")
    print(f"Batch size: {batch_size}; evaluating all {len(rules)} configured rules.")
    print("Ground-truth fields remain outside the Detection Engine.")

    for batch_number, batch in enumerate(iter_dataset_batches(batch_size=batch_size), start=1):
        features, ground_truth, actual = _validate_batch(batch, expected_start)
        overall_detections = overall_engine.evaluate(features)
        overall_predicted = _detected_series(features.index, overall_detections, "Overall")
        _update_counts(overall_counts, actual, overall_predicted)

        for rule in rules:
            detections = individual_engines[rule.rule_id].evaluate(features)
            predicted = _detected_series(features.index, detections, rule.rule_id)
            _update_counts(individual_counts[rule.rule_id], actual, predicted)

        # Third level: post-detection coverage by UNSW-NB15 attack_cat.
        attack_mask = actual.eq(1)
        attack_categories = ground_truth.loc[attack_mask, "attack_cat"].astype("string").str.strip()
        detected_attacks = overall_predicted.loc[attack_mask]
        for category, group_index in attack_categories.groupby(attack_categories).groups.items():
            category_counts[str(category)]["total_attack_records"] += len(group_index)
            category_counts[str(category)]["detected_attack_records"] += int(
                detected_attacks.loc[group_index].sum()
            )

        total_records += len(features)
        expected_start = batch.end_record_id + 1
        print(f"Processed batch {batch_number}: {total_records:,} records")

    if total_records == 0:
        raise RuntimeError("No dataset records were evaluated.")

    overall = _calculate_metrics(overall_counts)
    individual_rows = []
    for rule in rules:
        metrics = _calculate_metrics(individual_counts[rule.rule_id])
        individual_rows.append({
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "evaluation": "Individual rule vs binary Label",
            **metrics,
        })

    category_rows = []
    for category in sorted(category_counts):
        counts = category_counts[category]
        total = counts["total_attack_records"]
        detected = counts["detected_attack_records"]
        category_rows.append({
            "attack_category": category,
            "total_attack_records": total,
            "detected_attack_records": detected,
            "missed_attack_records": total - detected,
            "detection_rate": detected / total if total else 0.0,
        })
    total_attacks = sum(row["total_attack_records"] for row in category_rows)
    detected_attacks = sum(row["detected_attack_records"] for row in category_rows)
    # Cross-check the three evaluation levels before writing any output.
    if sum(overall_counts.values()) != total_records:
        raise RuntimeError("Overall confusion-matrix counts do not sum to all records.")
    if total_attacks != overall_counts["TP"] + overall_counts["FN"]:
        raise RuntimeError("Attack-category totals do not match binary ground truth.")
    if detected_attacks != overall_counts["TP"]:
        raise RuntimeError("Attack-category detections do not match overall true positives.")
    category_rows.append({
        "attack_category": "ALL_ATTACKS",
        "total_attack_records": total_attacks,
        "detected_attack_records": detected_attacks,
        "missed_attack_records": total_attacks - detected_attacks,
        "detection_rate": detected_attacks / total_attacks if total_attacks else 0.0,
    })

    _write_csv(RESULTS_DIR / "overall_metrics.csv", [{"evaluation": "Overall — all five rules", **overall}])
    _write_csv(RESULTS_DIR / "individual_rule_metrics.csv", individual_rows)
    _write_csv(RESULTS_DIR / "attack_category_analysis.csv", category_rows)
    _write_confusion_matrix(RESULTS_DIR / "overall_confusion_matrix.csv", overall_counts)
    for rule in rules:
        _write_confusion_matrix(
            RESULTS_DIR / f"confusion_matrix_{rule.rule_id.lower()}.csv",
            individual_counts[rule.rule_id],
        )
    _write_report(RESULTS_DIR / "evaluation_summary.txt", overall,
            individual_rows, category_rows, total_records)

    print("\nEvaluation completed.")
    print(f"Records evaluated: {total_records:,}")
    print(f"Overall Precision: {_percent(overall['precision'])}")
    print(f"Overall Recall: {_percent(overall['recall'])}")
    print(f"Overall F1-score: {_percent(overall['f1_score'])}")
    print(f"Attack-category rows: {len(category_rows) - 1}")
    print(f"Results directory: {RESULTS_DIR}")


if __name__ == "__main__":
    run_evaluation()
