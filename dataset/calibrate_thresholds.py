import numpy as np
import pandas as pd

from dataset.loader import load_dataset
from detection.config import DETECTION_THRESHOLDS


RULE_FEATURES = {
    "DOS-001": ("Sload", "Spkts"),
    "REC-001": ("ct_dst_src_ltm",),
    "EXP-001": ("trans_depth", "ct_flw_http_mthd"),
    "GEN-001": ("sbytes",),
    "CON-001": ("ct_srv_src", "ct_src_ltm")
}


def prepare_numeric_feature(series: pd.Series):
    """Convert a feature to finite numeric values and report invalid data."""

    numeric = pd.to_numeric(series, errors="coerce")

    missing_count = int(series.isna().sum())
    non_numeric_count = int(
        (series.notna() & numeric.isna()).sum()
    )

    numeric_array = numeric.to_numpy(dtype=float)
    infinite_mask = np.isinf(numeric_array)
    finite_mask = np.isfinite(numeric_array)

    finite_series = numeric.where(finite_mask)
    finite_values = finite_series.dropna()

    return {
        "series": finite_series,
        "values": finite_values,
        "missing": missing_count,
        "non_numeric": non_numeric_count,
        "infinite": int(infinite_mask.sum()),
        "valid": int(finite_mask.sum())
    }


def print_feature_statistics(
    feature_name: str,
    feature_data: dict,
    current_threshold: float
) -> None:
    """Print descriptive statistics for one detection feature."""

    values = feature_data["values"]

    print(f"\nFeature: {feature_name}")
    print(f"Valid numeric values: {feature_data['valid']:,}")
    print(f"Missing values: {feature_data['missing']:,}")
    print(f"Non-numeric values: {feature_data['non_numeric']:,}")
    print(f"Infinite values: {feature_data['infinite']:,}")

    if values.empty:
        print("No valid finite numeric values available.")
        return

    print(f"Minimum: {values.min():.4f}")
    print(f"Median (50%): {values.quantile(0.50):.4f}")
    print(f"90th percentile: {values.quantile(0.90):.4f}")
    print(f"95th percentile: {values.quantile(0.95):.4f}")
    print(f"99th percentile: {values.quantile(0.99):.4f}")
    print(f"99.5th percentile: {values.quantile(0.995):.4f}")
    print(f"Maximum: {values.max():.4f}")

    threshold_matches = int((values >= current_threshold).sum())
    threshold_percentile = (
        float((values <= current_threshold).sum())
        / len(values)
        * 100
    )

    print(f"Current configured threshold: {current_threshold}")
    print(f"Records at or above current threshold: {threshold_matches:,}")
    print(
        "Empirical percentile rank of current threshold: "
        f"{threshold_percentile:.2f}%"
    )


def analyze_rule_matches(
    numeric_features: dict,
    total_records: int
) -> None:
    """Count matches for each configured rule without using ground truth."""

    dos_sload = (
        numeric_features["Sload"]["values"]
        >= DETECTION_THRESHOLDS["dos_sload"]
    )
    dos_spkts = (
        numeric_features["Spkts"]["values"]
        >= DETECTION_THRESHOLDS["dos_spkts"]
    )

    rec_matches = (
        numeric_features["ct_dst_src_ltm"]["values"]
        >= DETECTION_THRESHOLDS["rec_ct_dst_src_ltm"]
    )

    exp_depth = (
        numeric_features["trans_depth"]["values"]
        >= DETECTION_THRESHOLDS["exp_trans_depth"]
    )
    exp_methods = (
        numeric_features["ct_flw_http_mthd"]["values"]
        >= DETECTION_THRESHOLDS["exp_http_methods"]
    )

    gen_matches = (
        numeric_features["sbytes"]["values"]
        >= DETECTION_THRESHOLDS["gen_sbytes"]
    )

    con_srv = (
        numeric_features["ct_srv_src"]["values"]
        >= DETECTION_THRESHOLDS["con_ct_srv_src"]
    )
    con_src = (
        numeric_features["ct_src_ltm"]["values"]
        >= DETECTION_THRESHOLDS["con_ct_src_ltm"]
    )

    dos_matches = dos_sload | dos_spkts
    exp_matches = exp_depth & exp_methods
    con_matches = con_srv & con_src

    results = [
        (
            "DOS-001",
            (
                f"Sload condition: {int(dos_sload.sum()):,}; "
                f"Spkts condition: {int(dos_spkts.sum()):,}"
            ),
            int(dos_matches.sum())
        ),
        (
            "REC-001",
            "Single-feature condition",
            int(rec_matches.sum())
        ),
        (
            "EXP-001",
            (
                f"trans_depth condition: {int(exp_depth.sum()):,}; "
                f"ct_flw_http_mthd condition: {int(exp_methods.sum()):,}"
            ),
            int(exp_matches.sum())
        ),
        (
            "GEN-001",
            "Single-feature condition",
            int(gen_matches.sum())
        ),
        (
            "CON-001",
            (
                f"ct_srv_src condition: {int(con_srv.sum()):,}; "
                f"ct_src_ltm condition: {int(con_src.sum()):,}"
            ),
            int(con_matches.sum())
        )
    ]

    print("\n========== CURRENT RULE CONDITION ANALYSIS ==========")
    print("Counts use configured thresholds and feature values only.")

    for rule_id, condition_details, match_count in results:
        percentage = (
            match_count / total_records * 100
            if total_records
            else 0
        )

        print(f"\n{rule_id}")
        print(condition_details)
        print(f"Combined rule matches: {match_count:,}")
        print(f"Share of dataset records: {percentage:.4f}%")


def analyze_thresholds():
    """Analyze feature distributions without accessing ground-truth data."""

    dataset = load_dataset()
    features = dataset.features

    required_features = {
        column
        for columns in RULE_FEATURES.values()
        for column in columns
    }

    missing_features = required_features - set(features.columns)

    if missing_features:
        raise ValueError(
            "Dataset is missing required detection features: "
            + ", ".join(sorted(missing_features))
        )

    numeric_features = {}

    print("\n========== DETECTION THRESHOLD ANALYSIS ==========")
    print(f"Total dataset records: {len(features):,}")
    print(f"Detection rules: {len(RULE_FEATURES)}")
    print("Ground-truth fields are not used in this analysis.")
    print(
        "Thresholds are descriptive preliminary values; "
        "this script does not modify detection configuration."
    )

    for rule_id, columns in RULE_FEATURES.items():
        print(f"\n--- {rule_id} ---")

        for column in columns:
            numeric_features[column] = prepare_numeric_feature(
                features[column]
            )

            threshold_key = {
                "Sload": "dos_sload",
                "Spkts": "dos_spkts",
                "ct_dst_src_ltm": "rec_ct_dst_src_ltm",
                "trans_depth": "exp_trans_depth",
                "ct_flw_http_mthd": "exp_http_methods",
                "sbytes": "gen_sbytes",
                "ct_srv_src": "con_ct_srv_src",
                "ct_src_ltm": "con_ct_src_ltm"
            }[column]

            print_feature_statistics(
                column,
                numeric_features[column],
                DETECTION_THRESHOLDS[threshold_key]
            )

    analyze_rule_matches(
        numeric_features,
        len(features)
    )

    print("\nThreshold analysis completed.")
    print("No detection rules or configured thresholds were modified.")


if __name__ == "__main__":
    analyze_thresholds()
