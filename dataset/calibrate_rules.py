"""
Calibrate the thresholds used by the CSIMS detection rules.

Run this file from the main project folder:

    python dataset/calibrate_rules.py --seed 2026

The script does not change detection/config.py. It creates a separate folder
with the proposed thresholds and the evaluation results.
"""

import argparse
import itertools
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_FOLDER = Path(__file__).resolve().parent.parent
if str(PROJECT_FOLDER) not in sys.path:
    sys.path.insert(0, str(PROJECT_FOLDER))

from dataset.loader import load_dataset
from detection.config import DETECTION_THRESHOLDS
from detection.rules import build_detection_rules
from detection.engine import DetectionEngine


RESULTS_FOLDER = Path(__file__).resolve().parent / "calibration_results"

SPLIT_PARTS = (0.60, 0.20, 0.20)
QUANTILES = (0.80, 0.85, 0.90, 0.95, 0.97, 0.98, 0.99, 0.995, 0.999)

RULE_THRESHOLDS = {
    "DOS-001": ("dos_sload", "dos_spkts"),
    "REC-001": ("rec_ct_dst_src_ltm",),
    "EXP-001": ("exp_trans_depth", "exp_http_methods"),
    "GEN-001": ("gen_sbytes",),
    "CON-001": ("con_ct_srv_src", "con_ct_src_ltm"),
}

RULE_FEATURES = {
    "dos_sload": "Sload",
    "dos_spkts": "Spkts",
    "rec_ct_dst_src_ltm": "ct_dst_src_ltm",
    "exp_trans_depth": "trans_depth",
    "exp_http_methods": "ct_flw_http_mthd",
    "gen_sbytes": "sbytes",
    "con_ct_srv_src": "ct_srv_src",
    "con_ct_src_ltm": "ct_src_ltm",
}


def calculate_metrics(actual, predicted):
    """Calculate the main binary classification metrics."""
    actual = np.asarray(actual, dtype=bool)
    predicted = np.asarray(predicted, dtype=bool)

    tp = int(np.sum(actual & predicted))
    fp = int(np.sum(~actual & predicted))
    tn = int(np.sum(~actual & ~predicted))
    fn = int(np.sum(actual & ~predicted))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    fpr = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / len(actual) if len(actual) else 0.0

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "accuracy": accuracy,
        "total_records": len(actual),
    }


def make_group_ids(features):
    """
    Give identical complete feature rows the same group number.

    Label and attack_cat are not included. A 64-bit pandas row hash is used
    so that the full dataset can be grouped without building large Python
    tuples for every record.
    """
    row_hashes = pd.util.hash_pandas_object(
        features, index=False
    ).to_numpy(dtype="uint64")

    _, group_ids = np.unique(row_hashes, return_inverse=True)
    return group_ids


def split_groups(group_ids, labels, seed):
    """
    Split complete feature groups into Calibration, Validation and Test.

    The assignment tries to keep the number of rows, attacks and normal
    records close to the requested 60/20/20 proportions. A group is never
    divided between two parts.
    """
    random = np.random.default_rng(seed)

    group_data = pd.DataFrame({
        "group_id": group_ids,
        "label": np.asarray(labels, dtype="int8"),
    })

    summary = group_data.groupby("group_id", sort=False).agg(
        records=("label", "size"),
        attacks=("label", "sum"),
    )
    summary["normal"] = summary["records"] - summary["attacks"]

    # Randomise groups with the same size before sorting them.
    summary = summary.iloc[random.permutation(len(summary))]
    summary = summary.sort_values("records", ascending=False, kind="stable")

    totals = np.array([
        summary["records"].sum(),
        summary["attacks"].sum(),
        summary["normal"].sum(),
    ], dtype=float)

    targets = np.array(SPLIT_PARTS)[:, None] * totals[None, :]
    current = np.zeros((3, 3), dtype=float)
    assigned_groups = [[], [], []]

    for group_id, row in summary.iterrows():
        group_counts = np.array(
            [row["records"], row["attacks"], row["normal"]],
            dtype=float,
        )

        best_split = None
        best_score = None

        for split_number in range(3):
            trial = current.copy()
            trial[split_number] += group_counts

            # Normalised squared distance from the requested split sizes.
            score = np.sum(
                ((trial - targets) / np.maximum(targets, 1.0)) ** 2
            )

            if best_score is None or score < best_score:
                best_score = score
                best_split = split_number

        current[best_split] += group_counts
        assigned_groups[best_split].append(int(group_id))

    group_to_split = np.full(int(group_ids.max()) + 1, -1, dtype=np.int8)

    for split_number, group_list in enumerate(assigned_groups):
        group_to_split[np.asarray(group_list, dtype=int)] = split_number

    row_split = group_to_split[group_ids]

    if np.any(row_split < 0):
        raise RuntimeError("Some feature groups were not assigned.")

    indexes = [
        np.flatnonzero(row_split == split_number)
        for split_number in range(3)
    ]

    # Check that no complete feature group appears in more than one split.
    group_sets = [
        set(group_ids[indexes[number]].tolist())
        for number in range(3)
    ]
    if (
        group_sets[0] & group_sets[1]
        or group_sets[0] & group_sets[2]
        or group_sets[1] & group_sets[2]
    ):
        raise RuntimeError("A duplicate feature group crossed split boundaries.")

    return indexes, summary, current


def prepare_rule_features(features):
    """Convert only the columns used by the rules to numeric values."""
    missing = [
        column for column in RULE_FEATURES.values()
        if column not in features.columns
    ]
    if missing:
        raise ValueError(
            "The dataset is missing rule features: " + ", ".join(missing)
        )

    result = features[list(RULE_FEATURES.values())].copy()

    for column in result.columns:
        result[column] = pd.to_numeric(result[column], errors="coerce")

    return result


def get_rule_predictions(features, thresholds):
    """
    Get predictions from the actual rule definitions in detection/rules.py.

    This avoids keeping a second, separate copy of the detection conditions
    inside the calibration script.
    """
    rules = build_detection_rules(thresholds)
    predictions = {}

    for rule in rules:
        result = rule.condition(features)
        predictions[rule.rule_id] = (
            result.fillna(False).astype(bool)
        )

    return predictions


def get_candidates(calibration_features, threshold_name, baseline_value):
    """Create threshold candidates from the Calibration part only."""
    column = RULE_FEATURES[threshold_name]

    values = (
        calibration_features[column]
        .replace([np.inf, -np.inf], np.nan)
        .dropna()
    )

    if values.empty:
        raise ValueError("No numeric values found for " + column)

    candidates = [float(baseline_value)]

    for quantile in QUANTILES:
        candidates.append(float(values.quantile(quantile)))

    candidates = sorted(set(
        value for value in candidates
        if np.isfinite(value)
        and value >= 0
        and (value > 0 or float(baseline_value) == 0)
    ))

    return candidates


def select_rule_thresholds(
    rule_id,
    calibration_features,
    validation_features,
    validation_labels,
    baseline,
):
    """Select one rule's thresholds using Validation, not Test."""
    threshold_names = RULE_THRESHOLDS[rule_id]

    baseline_predictions = get_rule_predictions(
        validation_features, baseline
    )
    baseline_result = calculate_metrics(
        validation_labels,
        baseline_predictions[rule_id],
    )

    candidates = {
        name: get_candidates(
            calibration_features, name, baseline[name]
        )
        for name in threshold_names
    }

    best_thresholds = {
        name: float(baseline[name]) for name in threshold_names
    }
    best_result = baseline_result
    best_score = (
        baseline_result["f1_score"],
        baseline_result["precision"],
        baseline_result["recall"],
        -baseline_result["false_positive_rate"],
    )

    checked = 0

    candidate_lists = [candidates[name] for name in threshold_names]

    for values in itertools.product(*candidate_lists):
        trial_thresholds = baseline.copy()
        trial_thresholds.update(dict(zip(threshold_names, values)))

        predictions = get_rule_predictions(
            validation_features, trial_thresholds
        )
        result = calculate_metrics(
            validation_labels, predictions[rule_id]
        )
        checked += 1

        # Do not accept a rule with a higher Validation FPR than its baseline.
        if (
            result["false_positive_rate"]
            > baseline_result["false_positive_rate"] + 1e-12
        ):
            continue

        score = (
            result["f1_score"],
            result["precision"],
            result["recall"],
            -result["false_positive_rate"],
        )

        if score > best_score:
            best_score = score
            best_result = result
            best_thresholds = {
                name: float(trial_thresholds[name])
                for name in threshold_names
            }

    return best_thresholds, best_result, checked


def evaluate_configuration(features, labels, thresholds):
    """Evaluate all rules together and each rule separately."""
    predictions = get_rule_predictions(features, thresholds)

    combined = np.zeros(len(features), dtype=bool)
    individual_results = []

    for rule_id in RULE_THRESHOLDS:
        current = predictions[rule_id].to_numpy(dtype=bool)
        combined |= current

        individual_results.append({
            "rule_id": rule_id,
            **calculate_metrics(labels, current),
        })

    overall_result = calculate_metrics(labels, combined)
    return overall_result, individual_results, combined


def check_engine_result(features, combined_predictions, thresholds):
    """
    Check that the rule conditions used above agree with DetectionEngine.

    This small check helps ensure that the offline metrics use the same
    rule logic as the application.
    """
    sample = features.iloc[:min(1000, len(features))].copy()
    rules = build_detection_rules(thresholds)
    engine = DetectionEngine(rules)
    incidents = engine.evaluate(sample)

    engine_predictions = pd.Series(False, index=sample.index)
    if not incidents.empty:
        engine_predictions.loc[incidents["source_record_id"]] = True

    expected = pd.Series(
        combined_predictions[:len(sample)],
        index=sample.index,
    )

    if not engine_predictions.equals(expected):
        raise RuntimeError(
            "Calibration predictions do not match DetectionEngine output."
        )


def write_csv(file_path, rows):
    pd.DataFrame(rows).to_csv(
        file_path, index=False, encoding="utf-8-sig"
    )


def run_calibration(seed):
    print("Loading the dataset through the project's Dataset Loader...")
    dataset = load_dataset()

    all_features = dataset.features
    rule_features = prepare_rule_features(all_features)

    labels = pd.to_numeric(
        dataset.ground_truth["Label"], errors="raise"
    )

    if labels.isna().any() or not labels.isin([0, 1]).all():
        raise ValueError("Label must contain only 0 and 1.")

    labels = labels.astype("int8").to_numpy()

    if len(all_features) != len(labels):
        raise ValueError("Feature and Label row counts do not match.")

    print("Grouping identical complete feature rows...")
    group_ids = make_group_ids(all_features)

    split_indexes, group_summary, split_counts = split_groups(
        group_ids, labels, seed
    )

    calibration_index, validation_index, test_index = split_indexes

    x_calibration = rule_features.iloc[calibration_index]
    x_validation = rule_features.iloc[validation_index]
    x_test = rule_features.iloc[test_index]

    y_calibration = labels[calibration_index]
    y_validation = labels[validation_index]
    y_test = labels[test_index]

    if min(len(x_calibration), len(x_validation), len(x_test)) == 0:
        raise RuntimeError("One of the data splits is empty.")

    baseline = {
        key: float(value)
        for key, value in DETECTION_THRESHOLDS.items()
    }
    proposed = baseline.copy()

    mixed_groups = (
        pd.DataFrame({"group_id": group_ids, "label": labels})
        .groupby("group_id")["label"]
        .nunique()
    )
    mixed_groups = mixed_groups[mixed_groups > 1]

    print(f"Total records: {len(all_features):,}")
    print(
        f"Calibration: {len(x_calibration):,}; "
        f"Validation: {len(x_validation):,}; "
        f"Test: {len(x_test):,}"
    )
    print(f"Groups with conflicting Label values: {len(mixed_groups):,}")
    print("Selecting thresholds on Validation...")

    selection_rows = []

    for rule_id, threshold_names in RULE_THRESHOLDS.items():
        selected, result, candidate_count = select_rule_thresholds(
            rule_id,
            x_calibration,
            x_validation,
            y_validation,
            baseline,
        )

        proposed.update(selected)

        for name in threshold_names:
            selection_rows.append({
                "rule_id": rule_id,
                "threshold": name,
                "baseline_value": baseline[name],
                "selected_value": proposed[name],
                "combinations_checked": candidate_count,
                "validation_precision": result["precision"],
                "validation_recall": result["recall"],
                "validation_f1": result["f1_score"],
                "validation_fpr": result["false_positive_rate"],
            })

        print(
            f"{rule_id}: {selected} "
            f"(Validation F1: {result['f1_score']:.4f})"
        )

    # The Test part is used only after all thresholds have been selected.
    baseline_overall, baseline_individual, baseline_predictions = (
        evaluate_configuration(x_test, y_test, baseline)
    )
    proposed_overall, proposed_individual, proposed_predictions = (
        evaluate_configuration(x_test, y_test, proposed)
    )

    check_engine_result(x_test, proposed_predictions, proposed)

    RESULTS_FOLDER.mkdir(parents=True, exist_ok=True)

    (RESULTS_FOLDER / "baseline_thresholds.json").write_text(
        json.dumps(baseline, indent=4), encoding="utf-8"
    )
    (RESULTS_FOLDER / "proposed_thresholds.json").write_text(
        json.dumps(proposed, indent=4), encoding="utf-8"
    )

    write_csv(
        RESULTS_FOLDER / "threshold_selection_validation.csv",
        selection_rows,
    )

    write_csv(
        RESULTS_FOLDER / "test_overall_comparison.csv",
        [
            {"configuration": "Baseline", **baseline_overall},
            {"configuration": "Proposed", **proposed_overall},
        ],
    )

    individual_rows = []
    for old_result, new_result in zip(
        baseline_individual, proposed_individual
    ):
        individual_rows.append({
            "configuration": "Baseline",
            **old_result,
        })
        individual_rows.append({
            "configuration": "Proposed",
            **new_result,
        })

    write_csv(
        RESULTS_FOLDER / "test_individual_rule_comparison.csv",
        individual_rows,
    )

    split_rows = []
    split_names = ("Calibration", "Validation", "Test")

    for split_number, split_name in enumerate(split_names):
        split_labels = labels[split_indexes[split_number]]
        split_rows.append({
            "split": split_name,
            "records": len(split_labels),
            "attacks": int(np.sum(split_labels == 1)),
            "normal": int(np.sum(split_labels == 0)),
            "attack_share": float(np.mean(split_labels == 1)),
            "unique_feature_groups": len(
                np.unique(group_ids[split_indexes[split_number]])
            ),
        })

    write_csv(RESULTS_FOLDER / "split_summary.csv", split_rows)

    conflict_rows = []
    if len(mixed_groups):
        conflict_data = pd.DataFrame({
            "group_id": group_ids,
            "label": labels,
        })
        for group_id, group in conflict_data.groupby("group_id"):
            if group["label"].nunique() > 1:
                conflict_rows.append({
                    "group_id": int(group_id),
                    "records": len(group),
                    "attack_labels": int((group["label"] == 1).sum()),
                    "normal_labels": int((group["label"] == 0).sum()),
                    "minimum_unavoidable_errors": min(
                        int((group["label"] == 1).sum()),
                        int((group["label"] == 0).sum()),
                    ),
                })

    if conflict_rows:
        write_csv(
            RESULTS_FOLDER / "conflicting_label_groups.csv",
            conflict_rows,
        )

    report = [
        "CSIMS DETECTION RULE CALIBRATION",
        "================================",
        "",
        "Dataset: UNSW-NB15_1.csv",
        f"Random seed: {seed}",
        f"Total records: {len(all_features):,}",
        "",
        "DATA SPLIT",
        "----------",
        "Complete feature rows were kept in one split.",
        "The split assignment considered row count, attack count and normal count.",
        "Label and attack_cat were not included in feature grouping.",
        f"Groups with conflicting Label values: {len(mixed_groups):,}",
        "",
        "GROUND TRUTH",
        "------------",
        "Label was used only for split balancing and evaluation.",
        "The Detection Engine received feature columns only.",
        "attack_cat was not used for threshold selection.",
        "",
        "THRESHOLD SELECTION",
        "-------------------",
        "Candidate values were calculated from Calibration features.",
        "Validation was used to select thresholds.",
        "Each rule was constrained not to exceed its baseline Validation FPR.",
        "Test was not used for candidate generation or threshold selection.",
        "",
        "TEST RESULTS — ALL RULES",
        "-------------------------",
    ]

    for name, result in (
        ("Baseline", baseline_overall),
        ("Proposed", proposed_overall),
    ):
        report.append(
            f"{name}: TP={result['TP']:,}, FP={result['FP']:,}, "
            f"TN={result['TN']:,}, FN={result['FN']:,}"
        )
        report.append(
            f"Precision={result['precision']:.4%}; "
            f"Recall={result['recall']:.4%}; "
            f"F1={result['f1_score']:.4%}; "
            f"FPR={result['false_positive_rate']:.4%}; "
            f"Accuracy={result['accuracy']:.4%}"
        )

    report.extend([
        "",
        "NOTES",
        "-----",
        "Each source record is counted once in the overall result, even if",
        "more than one detection rule matches it.",
        "Individual rule metrics are binary attack-versus-normal results.",
        "The script uses the real conditions from detection/rules.py.",
        "A small consistency check compares rule predictions with DetectionEngine.",
        "Groups with conflicting Label values are listed separately.",
        "A deterministic feature-only rule cannot assign different predictions",
        "to identical feature rows, even when their dataset labels conflict.",
        "The split prevents exact complete-feature duplicates from crossing parts.",
        "It does not prove independence between related network flows.",
        "The proposed thresholds are not copied into detection/config.py.",
        "Do not choose thresholds again based on Test results.",
    ])

    (RESULTS_FOLDER / "calibration_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )

    print("\nCalibration finished.")
    print(f"Baseline Test F1: {baseline_overall['f1_score']:.4%}")
    print(f"Proposed Test F1: {proposed_overall['f1_score']:.4%}")
    print(f"Results saved to: {RESULTS_FOLDER}")
    print("The production configuration was not changed.")


def main():
    parser = argparse.ArgumentParser(
        description="Calibrate CSIMS detection thresholds."
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=2026,
        help="Seed used for the grouped data split.",
    )
    args = parser.parse_args()

    run_calibration(args.seed)


if __name__ == "__main__":
    main()
