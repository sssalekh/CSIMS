import pandas as pd

from dataset.loader import load_dataset
from detection.engine import DetectionEngine
from detection.rules import build_detection_rules
from detection.config import DETECTION_THRESHOLDS


RULE_TARGET_CATEGORIES = {
    "DOS-001": {"dos"},
    "REC-001": {"reconnaissance"},
    "EXP-001": {"exploits"},
    "GEN-001": {
        "generic",
        "fuzzers",
        "backdoors",
        "analysis",
        "shellcode",
        "worms"
    },
    "CON-001": {
        "generic",
        "fuzzers",
        "backdoors",
        "analysis",
        "shellcode",
        "worms"
    }
}


CATEGORY_DISPLAY_NAMES = {
    "dos": "DoS",
    "reconnaissance": "Reconnaissance",
    "exploits": "Exploits",
    "generic": "Generic",
    "fuzzers": "Fuzzers",
    "backdoors": "Backdoors",
    "analysis": "Analysis",
    "shellcode": "Shellcode",
    "worms": "Worms"
}


def calculate_metrics(actual, predicted):
    if not actual.index.equals(predicted.index):
        raise ValueError(
            "Actual and predicted results must have identical indexes."
        )

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
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": precision,
        "Recall": recall,
        "F1-score": f1,
        "FPR": fpr
    }


def print_metrics(title, metrics):
    print(f"\n{title}")
    print("-" * 55)

    for name, value in metrics.items():
        if name in ("Precision", "Recall", "F1-score", "FPR"):
            print(f"{name}: {value:.4f} ({value * 100:.2f}%)")
        else:
            print(f"{name}: {value:,}")


def prepare_ground_truth(ground_truth, features):
    required_fields = {"Label", "attack_cat"}
    missing_fields = required_fields - set(ground_truth.columns)

    if missing_fields:
        raise ValueError(
            "Ground-truth data is missing required fields: "
            + ", ".join(sorted(missing_fields))
        )

    if not ground_truth.index.equals(features.index):
        raise ValueError(
            "Ground-truth and feature indexes do not match."
        )

    labels = pd.to_numeric(
        ground_truth["Label"],
        errors="raise"
    )

    if not labels.isin([0, 1]).all():
        raise ValueError("Label must contain only 0 and 1 values.")

    categories = (
        ground_truth["attack_cat"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.casefold()
    )

    known_categories = set(CATEGORY_DISPLAY_NAMES)
    positive_categories = set(categories[labels.eq(1)].unique())
    unknown_categories = positive_categories - known_categories

    if unknown_categories:
        raise ValueError(
            "Unknown attack categories found in positive records: "
            + ", ".join(sorted(unknown_categories))
        )

    return labels.eq(1), categories


def get_rule_predictions(rule, incidents, source_indexes):
    if incidents.empty:
        return pd.Series(False, index=source_indexes, dtype=bool)

    matching_ids = incidents.loc[
        incidents["matched_rule_ids"].apply(
            lambda rule_ids: rule.rule_id in rule_ids
        ),
        "source_record_id"
    ]

    return pd.Series(
        source_indexes.isin(matching_ids),
        index=source_indexes,
        dtype=bool
    )


def evaluate_detection():
    print("\n========== DETECTION ENGINE EVALUATION ==========")

    # 1. Load dataset.
    dataset = load_dataset()

    features = dataset.features
    ground_truth = dataset.ground_truth

    # 2. Build and execute the detection engine.
    # Ground-truth fields are kept separate from detection features.
    rules = build_detection_rules(DETECTION_THRESHOLDS)
    engine = DetectionEngine(rules)
    incidents = engine.evaluate(features)

    print(f"\nTotal dataset records: {len(features):,}")
    print(f"Total detection rules: {len(rules)}")
    print(f"Unique detected records: {len(incidents):,}")

    # 3. Prepare ground truth for evaluation only.
    actual_all, actual_categories = prepare_ground_truth(
        ground_truth,
        features
    )

    # 4. Evaluate each rule against its intended attack category.
    print("\n========== INDIVIDUAL RULE RESULTS ==========")

    for rule in rules:
        target_categories = RULE_TARGET_CATEGORIES.get(rule.rule_id)

        if target_categories is None:
            raise ValueError(
                f"No evaluation category mapping for {rule.rule_id}."
            )

        actual_rule = (
            actual_all
            & actual_categories.isin(target_categories)
        )

        predicted_rule = get_rule_predictions(
            rule,
            incidents,
            features.index
        )

        target_names = [
            CATEGORY_DISPLAY_NAMES[category]
            for category in sorted(target_categories)
        ]

        print(
            f"\nTarget category for {rule.rule_id}: "
            + ", ".join(target_names)
        )
        print(
            f"Actual positive records: {int(actual_rule.sum()):,}"
        )

        metrics = calculate_metrics(
            actual_rule,
            predicted_rule
        )

        print_metrics(rule.rule_id, metrics)

    # 5. Evaluate all rules together against all attack records.
    predicted_all = pd.Series(
        features.index.isin(incidents["source_record_id"])
        if not incidents.empty
        else False,
        index=features.index,
        dtype=bool
    )

    overall_metrics = calculate_metrics(
        actual_all,
        predicted_all
    )

    print("\n========== COMBINED DETECTION RESULTS ==========")
    print_metrics("All detection rules", overall_metrics)

    print("\nEvaluation completed.")


if __name__ == "__main__":
    evaluate_detection()
