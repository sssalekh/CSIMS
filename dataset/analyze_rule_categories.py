
from dataset.loader import load_dataset
from detection.engine import DetectionEngine
from detection.rules import build_detection_rules
from detection.config import DETECTION_THRESHOLDS


def analyze_rule_categories():

    print("\n========== ATTACK CATEGORY ANALYSIS ==========")

    # 1. Load dataset
    dataset = load_dataset()

    features = dataset.features
    ground_truth = dataset.ground_truth

    # 2. Execute detection
    rules = build_detection_rules(DETECTION_THRESHOLDS)
    engine = DetectionEngine(rules)

    incidents = engine.evaluate(features)

    # 3. Prepare ground truth for evaluation only
    evaluation_data = ground_truth.copy()

    evaluation_data["attack_cat"] = (
        evaluation_data["attack_cat"]
        .astype("string")
        .str.strip()
    )

    evaluation_data.index = features.index

    attack_records = evaluation_data[
        evaluation_data["Label"] == 1
    ]

    print(f"\nTotal attack records: {len(attack_records):,}")

    # 4. Analyze each rule by attack category
    for rule in rules:

        print(f"\n========== {rule.rule_id} ==========")

        if incidents.empty:
            detected_ids = set()
        else:
            matching_incidents = incidents[
                incidents["matched_rule_ids"].apply(
                    lambda ids: rule.rule_id in ids
                )
            ]

            detected_ids = set(
                matching_incidents["source_record_id"]
            )

        detected_attacks = attack_records.loc[
            attack_records.index.isin(detected_ids)
        ]

        category_totals = attack_records[
            "attack_cat"
        ].value_counts()

        category_detected = detected_attacks[
            "attack_cat"
        ].value_counts()

        results = []

        for category, total in category_totals.items():

            detected = int(category_detected.get(category, 0))

            recall = detected / total if total else 0

            results.append({
                "Category": category,
                "Total attacks": int(total),
                "Detected": detected,
                "Missed": int(total - detected),
                "Recall (%)": round(recall * 100, 2)
            })

        for result in results:
            print(
                f"{result['Category']}: "
                f"Total={result['Total attacks']}, "
                f"Detected={result['Detected']}, "
                f"Missed={result['Missed']}, "
                f"Recall={result['Recall (%)']}%"
            )

        print(
            "\nTotal attacks detected by this rule:",
            len(detected_attacks)
        )

    # 5. Analyze overlap between rules
    print("\n========== RULE OVERLAP ==========")

    if incidents.empty:
        print("No incidents detected.")
    else:
        overlap = incidents[
            "matched_rule_ids"
        ].apply(len).value_counts().sort_index()

        for rule_count, record_count in overlap.items():
            print(
                f"Records matched by {rule_count} rule(s): "
                f"{record_count:,}"
            )

    print("\nAnalysis completed.")


if __name__ == "__main__":
    analyze_rule_categories()
