import itertools

import numpy as np
import pandas as pd

from dataset.loader import load_dataset
from detection.rules import build_detection_rules
from detection.config import DETECTION_THRESHOLDS


# Evaluation mapping only; these categories are never passed to detection rules.
RULE_TARGET_CATEGORIES = {
    "DOS-001": {"dos"},
    "REC-001": {"reconnaissance"},
    "EXP-001": {"exploits"},
    "GEN-001": {
        "generic", "fuzzers", "backdoors",
        "analysis", "shellcode", "worms"
    },
    "CON-001": {
        "generic", "fuzzers", "backdoors",
        "analysis", "shellcode", "worms"
    }
}

RULE_FEATURES = {
    "dos_sload": "Sload",
    "dos_spkts": "Spkts",
    "rec_ct_dst_src_ltm": "ct_dst_src_ltm",
    "exp_trans_depth": "trans_depth",
    "exp_http_methods": "ct_flw_http_mthd",
    "gen_sbytes": "sbytes",
    "con_ct_srv_src": "ct_srv_src",
    "con_ct_src_ltm": "ct_src_ltm"
}

RULE_THRESHOLD_KEYS = {
    "DOS-001": ("dos_sload", "dos_spkts"),
    "REC-001": ("rec_ct_dst_src_ltm",),
    "EXP-001": ("exp_trans_depth", "exp_http_methods"),
    "GEN-001": ("gen_sbytes",),
    "CON-001": ("con_ct_srv_src", "con_ct_src_ltm")
}

CANDIDATE_PERCENTILES = [90, 95, 97, 98, 99, 99.5, 99.9]
CALIBRATION_SHARE = 0.70
RANDOM_SEED = 42


def calculate_metrics(actual, predicted):
    if not actual.index.equals(predicted.index):
        raise ValueError("Actual and predicted indexes must match.")

    actual = actual.astype(bool)
    predicted = predicted.astype(bool)

    tp = int((actual & predicted).sum())
    fp = int((~actual & predicted).sum())
    tn = int((~actual & ~predicted).sum())
    fn = int((actual & ~predicted).sum())

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )
    fpr = fp / (fp + tn) if fp + tn else 0

    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "Precision": precision, "Recall": recall,
        "F1-score": f1, "FPR": fpr
    }


def print_metrics(title, metrics):
    print(f"\n{title}")
    print("-" * 58)

    for name, value in metrics.items():
        if name in ("Precision", "Recall", "F1-score", "FPR"):
            print(f"{name}: {value:.4f} ({value * 100:.2f}%)")
        else:
            print(f"{name}: {value:,}")


def prepare_ground_truth(ground_truth, features):
    required = {"Label", "attack_cat"}
    missing = required - set(ground_truth.columns)

    if missing:
        raise ValueError(
            "Missing ground-truth fields: " + ", ".join(sorted(missing))
        )

    if not ground_truth.index.equals(features.index):
        raise ValueError("Ground-truth and feature indexes do not match.")

    labels = pd.to_numeric(ground_truth["Label"], errors="raise")

    if not labels.isin([0, 1]).all():
        raise ValueError("Label must contain only 0 and 1.")

    categories = (
        ground_truth["attack_cat"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.casefold()
    )

    known = set().union(*RULE_TARGET_CATEGORIES.values())
    unknown = set(categories[labels.eq(1)].unique()) - known

    if unknown:
        raise ValueError(
            "Unknown positive attack categories: "
            + ", ".join(sorted(unknown))
        )

    return labels.eq(1), categories


def split_dataset(features, actual, categories):
    rng = np.random.default_rng(RANDOM_SEED)
    positions = rng.permutation(len(features))
    calibration_size = int(len(features) * CALIBRATION_SHARE)

    calibration_positions = positions[:calibration_size]
    test_positions = positions[calibration_size:]

    return (
        features.iloc[calibration_positions].copy(),
        features.iloc[test_positions].copy(),
        actual.iloc[calibration_positions],
        actual.iloc[test_positions],
        categories.iloc[calibration_positions],
        categories.iloc[test_positions]
    )


def build_rule_targets(actual, categories):
    return {
        rule_id: actual & categories.isin(target_categories)
        for rule_id, target_categories in RULE_TARGET_CATEGORIES.items()
    }


def get_rule_condition(rule_id, thresholds):
    for rule in build_detection_rules(thresholds):
        if rule.rule_id == rule_id:
            return rule.condition

    raise ValueError(f"Detection rule not found: {rule_id}")


def get_predictions(rule_id, thresholds, features):
    predicted = get_rule_condition(rule_id, thresholds)(features)

    if not isinstance(predicted, pd.Series):
        raise TypeError(f"Rule {rule_id} must return a pandas Series.")

    if not predicted.index.equals(features.index):
        raise ValueError(f"Rule {rule_id} returned an invalid index.")

    return predicted.fillna(False).astype(bool)


def get_candidate_values(features, threshold_key, current_threshold):
    column = RULE_FEATURES[threshold_key]
    values = pd.to_numeric(
        features[column], errors="coerce"
    ).replace([np.inf, -np.inf], np.nan).dropna()

    if values.empty:
        raise ValueError(f"No valid numeric values for {column}.")

    candidates = [
        float(values.quantile(p / 100, interpolation="higher"))
        for p in CANDIDATE_PERCENTILES
    ]

    candidates.append(float(current_threshold))
    return sorted(set(candidates))


def tune_rule(rule_id, features, actual_target, current_thresholds):
    keys = RULE_THRESHOLD_KEYS[rule_id]
    candidate_lists = [
        get_candidate_values(features, key, current_thresholds[key])
        for key in keys
    ]

    best_thresholds = None
    best_metrics = None
    best_score = None
    candidate_count = 0

    for values in itertools.product(*candidate_lists):
        candidate_count += 1
        thresholds = current_thresholds.copy()

        for key, value in zip(keys, values):
            thresholds[key] = value

        predicted = get_predictions(rule_id, thresholds, features)
        metrics = calculate_metrics(actual_target, predicted)
        score = (
            metrics["F1-score"],
            metrics["Precision"],
            metrics["Recall"]
        )

        if best_score is None or score > best_score:
            best_score = score
            best_thresholds = {key: thresholds[key] for key in keys}
            best_metrics = metrics

    return best_thresholds, best_metrics, candidate_count


def evaluate_configuration(
    title, thresholds, features, actual_all, actual_targets
):
    print(f"\n========== {title} ==========")
    combined = pd.Series(False, index=features.index, dtype=bool)

    for rule_id in RULE_THRESHOLD_KEYS:
        predicted = get_predictions(rule_id, thresholds, features)
        combined |= predicted

        metrics = calculate_metrics(
            actual_targets[rule_id], predicted
        )
        print_metrics(f"{rule_id} — intended target categories", metrics)

    overall = calculate_metrics(actual_all, combined)
    print_metrics("All rules combined — all attack records", overall)
    return overall


def print_thresholds(title, thresholds):
    print(f"\n{title}")

    for rule_id, keys in RULE_THRESHOLD_KEYS.items():
        values = ", ".join(
            f"{key}={thresholds[key]:g}" for key in keys
        )
        print(f"{rule_id}: {values}")


def tune_detection_thresholds():
    print("\n========== DETECTION THRESHOLD TUNING ==========")
    print("Offline analysis only. Production configuration is not modified.")
    print("Ground-truth fields are used only for evaluation and calibration.")
    print(
        f"Calibration subset: {CALIBRATION_SHARE:.0%}; "
        f"independent test subset: {1 - CALIBRATION_SHARE:.0%}"
    )
    print(f"Random seed: {RANDOM_SEED}")

    dataset = load_dataset()
    features = dataset.features
    actual_all, categories = prepare_ground_truth(
        dataset.ground_truth, features
    )

    (
        calibration_features,
        test_features,
        calibration_actual,
        test_actual,
        calibration_categories,
        test_categories
    ) = split_dataset(features, actual_all, categories)

    calibration_targets = build_rule_targets(
        calibration_actual, calibration_categories
    )
    test_targets = build_rule_targets(test_actual, test_categories)

    print(f"\nTotal records: {len(features):,}")
    print(f"Calibration records: {len(calibration_features):,}")
    print(f"Independent test records: {len(test_features):,}")
    print("The random split does not use Label or attack_cat.")

    current = DETECTION_THRESHOLDS.copy()

    evaluate_configuration(
        "CURRENT CONFIGURATION — CALIBRATION SUBSET",
        current, calibration_features,
        calibration_actual, calibration_targets
    )
    evaluate_configuration(
        "CURRENT CONFIGURATION — INDEPENDENT TEST SUBSET",
        current, test_features, test_actual, test_targets
    )

    tuned = current.copy()

    print("\n========== THRESHOLD SELECTION ==========")
    print("Rules are tuned independently using calibration records only.")

    for rule_id in RULE_THRESHOLD_KEYS:
        best_values, metrics, count = tune_rule(
            rule_id,
            calibration_features,
            calibration_targets[rule_id],
            current
        )
        tuned.update(best_values)

        print(f"\n{rule_id} — candidates evaluated: {count}")

        for key, value in best_values.items():
            print(f"Selected {key}: {value:g}")

        print_metrics("Best calibration-subset metrics", metrics)

    print_thresholds("SELECTED CANDIDATE THRESHOLDS", tuned)

    # The independent test subset is evaluated only after threshold selection.
    evaluate_configuration(
        "TUNED CONFIGURATION — INDEPENDENT TEST SUBSET",
        tuned, test_features, test_actual, test_targets
    )

    print("\n========== IMPORTANT NOTES ==========")
    print("1. No production file or database was changed.")
    print(
        "2. Detection conditions are reused from build_detection_rules(); "
        "ground-truth fields are not passed to them."
    )
    print("3. Threshold selection uses calibration-subset F1-score.")
    print(
        "4. Independent test metrics show whether the selected thresholds "
        "generalise to unseen records."
    )
    print(
        "5. The target-category mapping is an agreed evaluation assumption; "
        "it does not change incident categories."
    )
    print(
        "6. Do not copy selected values into config.py before reviewing "
        "the independent test results and thesis alignment."
    )
    print("\nThreshold tuning analysis completed.")


if __name__ == "__main__":
    tune_detection_thresholds()
