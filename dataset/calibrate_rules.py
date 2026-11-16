"""
Calibrate and evaluate the thresholds used by the CSIMS detection rules.

Run this file from the main project folder:

    python dataset/calibrate_rules.py --seed 2026

Procedure
---------
1. The dataset is loaded through the project's Dataset Loader. Detection
   features and ground truth are kept separate.
2. Identical complete feature rows are grouped, and the groups are split at
   random into Calibration (60%), Validation (20%) and Test (20%). The split
   is stratified by Label so that each part keeps the same attack share, and
   a group never crosses two parts.
3. Candidate thresholds are taken from the Calibration part only.
4. For each rule, the candidate with the highest Validation F1-score is
   selected, provided that the rule's Validation false positive rate does not
   exceed MAX_RULE_FPR (the alert budget of one rule).
5. The Test part is used once, after all thresholds have been selected, to
   compare three configurations:
     - Version 1: the original rule set and thresholds (before redesign);
     - Initial:   the redesigned rules with the initial thresholds;
     - Proposed:  the redesigned rules with the selected thresholds.

The script does not change detection/config.py. It writes its results to
dataset/calibration_results/.
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
from detection.config import INITIAL_DETECTION_THRESHOLDS
from detection.rules import build_detection_rules
from detection.engine import DetectionEngine


RESULTS_FOLDER = Path(__file__).resolve().parent / "calibration_results"

SPLIT_PARTS = (0.60, 0.20, 0.20)
SPLIT_NAMES = ("Calibration", "Validation", "Test")

# Maximum false positive rate accepted for one rule on Validation.
MAX_RULE_FPR = 0.01

QUANTILES = (
    0.01, 0.02, 0.05, 0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70,
    0.80, 0.85, 0.90, 0.95, 0.97, 0.98, 0.99, 0.995, 0.999,
)

RULE_ORDER = ("DOS-001", "REC-001", "EXP-001", "GEN-001", "CON-001")

# Thresholds selected for each rule. GEN-001 has no numeric threshold.
RULE_THRESHOLDS = {
    "DOS-001": ("dos_sload",),
    "REC-001": ("rec_max_dbytes",),
    "EXP-001": ("exp_tcprtt",),
    "GEN-001": (),
    "CON-001": ("con_dns_max_sbytes",),
}

THRESHOLD_FEATURES = {
    "dos_sload": "Sload",
    "rec_max_dbytes": "dbytes",
    "exp_tcprtt": "tcprtt",
    "con_dns_max_sbytes": "sbytes",
}


# ------------------------------------------------------------------
# Version 1 rules (before redesign). Used only for comparison.
# ------------------------------------------------------------------

VERSION_1_THRESHOLDS = {
    "dos_sload": 132000000,
    "dos_spkts": 426,
    "rec_ct_dst_src_ltm": 11,
    "exp_trans_depth": 2,
    "exp_http_methods": 6,
    "gen_sbytes": 37500,
    "con_ct_srv_src": 23,
    "con_ct_src_ltm": 23,
}

VERSION_1_FEATURES = (
    "Sload", "Spkts", "ct_dst_src_ltm", "trans_depth",
    "ct_flw_http_mthd", "sbytes", "ct_srv_src", "ct_src_ltm",
)


def version_1_predictions(features):
    """Return the predictions of the original five rules."""
    t = VERSION_1_THRESHOLDS
    x = {
        column: pd.to_numeric(features[column], errors="coerce")
        for column in VERSION_1_FEATURES
    }
    return {
        "DOS-001": (x["Sload"] >= t["dos_sload"])
        | (x["Spkts"] >= t["dos_spkts"]),
        "REC-001": x["ct_dst_src_ltm"] >= t["rec_ct_dst_src_ltm"],
        "EXP-001": (x["trans_depth"] >= t["exp_trans_depth"])
        & (x["ct_flw_http_mthd"] >= t["exp_http_methods"]),
        "GEN-001": x["sbytes"] >= t["gen_sbytes"],
        "CON-001": (x["ct_srv_src"] >= t["con_ct_srv_src"])
        & (x["ct_src_ltm"] >= t["con_ct_src_ltm"]),
    }


# ------------------------------------------------------------------
# Metrics
# ------------------------------------------------------------------

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


# ------------------------------------------------------------------
# Data split
# ------------------------------------------------------------------

def make_group_ids(features):
    """
    Give identical complete feature rows the same group number.

    Label and attack_cat are not included. A 64-bit pandas row hash is used
    so that the full dataset can be grouped efficiently.
    """
    row_hashes = pd.util.hash_pandas_object(
        features, index=False
    ).to_numpy(dtype="uint64")

    _, group_ids = np.unique(row_hashes, return_inverse=True)
    return group_ids


def split_groups(group_ids, labels, seed):
    """
    Split complete feature groups at random into Calibration, Validation
    and Test, stratified by Label.

    Groups are shuffled separately for normal and attack groups and assigned
    by their cumulative number of records, so each part receives about
    60/20/20 of both classes. A group is never divided between two parts.
    A group containing both labels is treated as an attack group.
    """
    random = np.random.default_rng(seed)

    group_data = pd.DataFrame({
        "group_id": group_ids,
        "label": np.asarray(labels, dtype="int8"),
    })
    summary = group_data.groupby("group_id").agg(
        records=("label", "size"),
        has_attack=("label", "max"),
    )

    boundaries = np.cumsum(SPLIT_PARTS)[:-1]
    group_split = np.empty(len(summary), dtype=np.int8)

    for label_value in (0, 1):
        positions = np.flatnonzero(
            summary["has_attack"].to_numpy() == label_value
        )
        positions = random.permutation(positions)
        sizes = summary["records"].to_numpy()[positions]
        if len(positions) == 0:
            continue
        # Use the centre of each group to decide where it belongs.
        centre = (np.cumsum(sizes) - sizes / 2) / sizes.sum()
        group_split[positions] = np.searchsorted(
            boundaries, centre, side="right"
        )

    group_to_split = pd.Series(group_split, index=summary.index)
    row_split = group_to_split.loc[group_ids].to_numpy()

    indexes = [
        np.flatnonzero(row_split == number)
        for number in range(len(SPLIT_PARTS))
    ]

    group_sets = [set(group_ids[index].tolist()) for index in indexes]
    for first, second in itertools.combinations(range(3), 2):
        if group_sets[first] & group_sets[second]:
            raise RuntimeError(
                "A duplicate feature group crossed split boundaries."
            )

    return indexes


# ------------------------------------------------------------------
# Rule predictions and threshold selection
# ------------------------------------------------------------------

def rule_feature_columns():
    """Return every feature column used by the redesigned rules."""
    columns = []
    for rule in build_detection_rules(INITIAL_DETECTION_THRESHOLDS):
        for column in rule.required_features:
            if column not in columns:
                columns.append(column)
    return columns


def get_rule_predictions(features, thresholds):
    """
    Get predictions from the actual rule definitions in detection/rules.py.

    This avoids keeping a second copy of the detection conditions here.
    """
    predictions = {}
    for rule in build_detection_rules(thresholds):
        result = rule.condition(features)
        predictions[rule.rule_id] = result.fillna(False).astype(bool)
    return predictions


def get_candidates(calibration_features, threshold_name, initial_value):
    """Create threshold candidates from the Calibration part only."""
    column = THRESHOLD_FEATURES[threshold_name]

    values = (
        pd.to_numeric(calibration_features[column], errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .dropna()
    )

    if values.empty:
        raise ValueError("No numeric values found for " + column)

    candidates = {float(initial_value)}
    candidates.update(float(values.quantile(q)) for q in QUANTILES)

    return sorted(
        value for value in candidates
        if np.isfinite(value) and value >= 0
    )


def select_rule_thresholds(
    rule_id,
    calibration_features,
    validation_features,
    validation_labels,
    initial,
):
    """Select one rule's thresholds using Validation, not Test."""
    threshold_names = RULE_THRESHOLDS[rule_id]

    initial_result = calculate_metrics(
        validation_labels,
        get_rule_predictions(validation_features, initial)[rule_id],
    )

    if not threshold_names:
        return {}, initial_result, 0

    candidate_lists = [
        get_candidates(calibration_features, name, initial[name])
        for name in threshold_names
    ]

    best_thresholds = None
    best_result = None
    best_score = None
    checked = 0

    for values in itertools.product(*candidate_lists):
        trial = dict(initial)
        trial.update(dict(zip(threshold_names, values)))

        result = calculate_metrics(
            validation_labels,
            get_rule_predictions(validation_features, trial)[rule_id],
        )
        checked += 1

        if result["false_positive_rate"] > MAX_RULE_FPR + 1e-12:
            continue

        score = (
            result["f1_score"],
            result["precision"],
            -result["false_positive_rate"],
        )

        if best_score is None or score > best_score:
            best_score = score
            best_result = result
            best_thresholds = {
                name: float(trial[name]) for name in threshold_names
            }

    if best_thresholds is None:
        # No candidate satisfies the alert budget: keep the initial value.
        best_thresholds = {
            name: float(initial[name]) for name in threshold_names
        }
        best_result = initial_result

    return best_thresholds, best_result, checked


def evaluate_predictions(predictions, labels):
    """Evaluate all rules together and each rule separately."""
    combined = np.zeros(len(labels), dtype=bool)
    individual = []

    for rule_id in RULE_ORDER:
        current = np.asarray(predictions[rule_id], dtype=bool)
        combined |= current
        individual.append({
            "rule_id": rule_id,
            **calculate_metrics(labels, current),
        })

    return calculate_metrics(labels, combined), individual, combined


def category_detection(attack_categories, labels, combined):
    """Detection rate within each UNSW-NB15 attack category (Test only)."""
    rows = []
    attacks = labels == 1
    categories = attack_categories[attacks]
    detected = combined[attacks]

    for category in sorted(set(categories)):
        mask = categories == category
        total = int(mask.sum())
        found = int(detected[mask].sum())
        rows.append({
            "attack_cat": category,
            "attacks": total,
            "detected": found,
            "missed": total - found,
            "detection_rate": found / total if total else 0.0,
        })

    return rows


def check_engine_result(features, combined_predictions, thresholds):
    """
    Check that the rule conditions used above agree with DetectionEngine,
    so the offline metrics use the same logic as the application.
    """
    sample = features.iloc[:min(5000, len(features))].copy()
    incidents = DetectionEngine(
        build_detection_rules(thresholds)
    ).evaluate(sample)

    engine_predictions = pd.Series(False, index=sample.index)
    if not incidents.empty:
        engine_predictions.loc[incidents["source_record_id"]] = True

    expected = pd.Series(
        combined_predictions[:len(sample)], index=sample.index
    )

    if not engine_predictions.equals(expected):
        raise RuntimeError(
            "Calibration predictions do not match DetectionEngine output."
        )


def write_csv(file_path, rows):
    pd.DataFrame(rows).to_csv(file_path, index=False, encoding="utf-8-sig")


def metric_line(result):
    return (
        f"TP={result['TP']:,}, FP={result['FP']:,}, "
        f"TN={result['TN']:,}, FN={result['FN']:,}; "
        f"Precision={result['precision']:.2%}; "
        f"Recall={result['recall']:.2%}; "
        f"F1={result['f1_score']:.2%}; "
        f"FPR={result['false_positive_rate']:.2%}"
    )


# ------------------------------------------------------------------
# Main procedure
# ------------------------------------------------------------------

def run_calibration(seed):
    print("Loading the dataset through the project's Dataset Loader...")
    dataset = load_dataset()

    all_features = dataset.features

    labels = pd.to_numeric(dataset.ground_truth["Label"], errors="raise")
    if labels.isna().any() or not labels.isin([0, 1]).all():
        raise ValueError("Label must contain only 0 and 1.")
    labels = labels.astype("int8").to_numpy()

    attack_categories = (
        dataset.ground_truth["attack_cat"]
        .astype("string").str.strip().fillna("Normal")
        .replace("", "Normal")
        .to_numpy(dtype=object)
    )

    if len(all_features) != len(labels):
        raise ValueError("Feature and Label row counts do not match.")

    columns = rule_feature_columns()
    rule_features = all_features[columns]
    version_1_features = all_features[list(VERSION_1_FEATURES)]

    print("Grouping identical complete feature rows...")
    group_ids = make_group_ids(all_features)
    split_indexes = split_groups(group_ids, labels, seed)
    calibration_index, validation_index, test_index = split_indexes

    x_calibration = rule_features.iloc[calibration_index]
    x_validation = rule_features.iloc[validation_index]
    x_test = rule_features.iloc[test_index]
    y_validation = labels[validation_index]
    y_test = labels[test_index]

    if min(len(x_calibration), len(x_validation), len(x_test)) == 0:
        raise RuntimeError("One of the data splits is empty.")

    mixed_groups = (
        pd.DataFrame({"group_id": group_ids, "label": labels})
        .groupby("group_id")["label"].nunique()
    )
    mixed_group_count = int((mixed_groups > 1).sum())

    print(f"Total records: {len(all_features):,}")
    for name, index in zip(SPLIT_NAMES, split_indexes):
        print(f"  {name}: {len(index):,} records, "
              f"{int(labels[index].sum()):,} attacks")
    print("Selecting thresholds on Validation...")

    initial = {
        key: float(value)
        for key, value in INITIAL_DETECTION_THRESHOLDS.items()
    }
    proposed = dict(initial)
    selection_rows = []

    for rule_id in RULE_ORDER:
        selected, result, checked = select_rule_thresholds(
            rule_id, x_calibration, x_validation, y_validation, initial
        )
        proposed.update(selected)

        names = RULE_THRESHOLDS[rule_id] or ("(no numeric threshold)",)
        for name in names:
            selection_rows.append({
                "rule_id": rule_id,
                "threshold": name,
                "initial_value": initial.get(name, ""),
                "selected_value": proposed.get(name, ""),
                "candidates_checked": checked,
                "validation_precision": result["precision"],
                "validation_recall": result["recall"],
                "validation_f1": result["f1_score"],
                "validation_fpr": result["false_positive_rate"],
            })

        print(f"  {rule_id}: {selected or 'no threshold'} "
              f"(Validation F1 {result['f1_score']:.4f}, "
              f"FPR {result['false_positive_rate']:.4%})")

    # The Test part is used only after all thresholds have been selected.
    configurations = {
        "Version 1": version_1_predictions(
            version_1_features.iloc[test_index]
        ),
        "Initial": get_rule_predictions(x_test, initial),
        "Proposed": get_rule_predictions(x_test, proposed),
    }

    overall_rows = []
    individual_rows = []
    combined_by_name = {}

    for name, predictions in configurations.items():
        overall, individual, combined = evaluate_predictions(
            predictions, y_test
        )
        combined_by_name[name] = (overall, individual, combined)
        overall_rows.append({"configuration": name, **overall})
        for row in individual:
            individual_rows.append({"configuration": name, **row})

    check_engine_result(
        x_test, combined_by_name["Proposed"][2], proposed
    )

    category_rows = []
    for name in ("Version 1", "Proposed"):
        for row in category_detection(
            attack_categories[test_index], y_test,
            combined_by_name[name][2],
        ):
            category_rows.append({"configuration": name, **row})

    split_rows = []
    for name, index in zip(SPLIT_NAMES, split_indexes):
        split_labels = labels[index]
        split_rows.append({
            "split": name,
            "records": len(split_labels),
            "attacks": int(np.sum(split_labels == 1)),
            "normal": int(np.sum(split_labels == 0)),
            "attack_share": float(np.mean(split_labels == 1)),
            "unique_feature_groups": len(np.unique(group_ids[index])),
        })

    RESULTS_FOLDER.mkdir(parents=True, exist_ok=True)
    for old_file in RESULTS_FOLDER.glob("*"):
        if old_file.is_file():
            old_file.unlink()

    (RESULTS_FOLDER / "initial_thresholds.json").write_text(
        json.dumps(initial, indent=4), encoding="utf-8"
    )
    (RESULTS_FOLDER / "proposed_thresholds.json").write_text(
        json.dumps(proposed, indent=4), encoding="utf-8"
    )
    write_csv(RESULTS_FOLDER / "split_summary.csv", split_rows)
    write_csv(
        RESULTS_FOLDER / "threshold_selection_validation.csv",
        selection_rows,
    )
    write_csv(RESULTS_FOLDER / "test_overall_comparison.csv", overall_rows)
    write_csv(
        RESULTS_FOLDER / "test_individual_rule_comparison.csv",
        individual_rows,
    )
    write_csv(
        RESULTS_FOLDER / "test_attack_category_detection.csv",
        category_rows,
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
        "Identical complete feature rows form one group; a group is never",
        "divided between two parts. Groups were assigned at random,",
        "stratified by Label (60% / 20% / 20%).",
        f"Groups with conflicting Label values: {mixed_group_count:,}",
    ]
    for row in split_rows:
        report.append(
            f"{row['split']}: {row['records']:,} records, "
            f"{row['attacks']:,} attacks ({row['attack_share']:.2%})"
        )

    report += [
        "",
        "GROUND TRUTH",
        "------------",
        "Label was used only for split stratification, threshold selection",
        "on Validation and evaluation. The rules received feature columns",
        "only. attack_cat was used only for the category analysis on Test.",
        "",
        "THRESHOLD SELECTION",
        "-------------------",
        "Candidates: the initial value and quantiles of the Calibration part.",
        "Selection: highest Validation F1-score for each rule, with the",
        f"rule's Validation FPR not exceeding {MAX_RULE_FPR:.0%}.",
        "Test was not used for candidate generation or selection.",
    ]
    for row in selection_rows:
        report.append(
            f"{row['rule_id']} {row['threshold']}: "
            f"{row['initial_value']} -> {row['selected_value']}"
        )

    report += ["", "TEST RESULTS - ALL RULES", "------------------------"]
    for name, (overall, _, _) in combined_by_name.items():
        report.append(f"{name}: {metric_line(overall)}")

    report += ["", "TEST RESULTS - INDIVIDUAL RULES", "-------------------------------"]
    for name, (_, individual, _) in combined_by_name.items():
        report.append(name)
        for row in individual:
            report.append(f"  {row['rule_id']}: {metric_line(row)}")

    report += [
        "",
        "NOTES",
        "-----",
        "Version 1 is the original rule set before redesign.",
        "Each source record is counted once in the overall result, even if",
        "more than one rule matches it. Individual rule metrics compare one",
        "rule with the binary Label, so a rule aimed at one kind of",
        "behaviour cannot reach a high recall on all attacks by itself.",
        "The split prevents exact duplicates from crossing parts; it does",
        "not prove independence between related network flows.",
        "Do not choose thresholds again based on Test results.",
    ]

    (RESULTS_FOLDER / "calibration_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )

    print("\nTest results (all rules):")
    for name, (overall, _, _) in combined_by_name.items():
        print(f"  {name}: {metric_line(overall)}")
    print(f"Results saved to: {RESULTS_FOLDER}")
    print("detection/config.py was not changed.")


def main():
    parser = argparse.ArgumentParser(
        description="Calibrate CSIMS detection thresholds."
    )
    parser.add_argument(
        "--seed", type=int, default=2026,
        help="Seed used for the grouped data split.",
    )
    args = parser.parse_args()
    run_calibration(args.seed)


if __name__ == "__main__":
    main()
