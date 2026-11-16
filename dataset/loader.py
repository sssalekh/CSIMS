
from dataclasses import dataclass
from pathlib import Path
import re

import pandas as pd


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

DATASET_FILE = DATA_DIR / "UNSW-NB15_1.csv"
FEATURES_FILE = DATA_DIR / "UNSW-NB15_features.csv"

# Ground-truth fields must never enter the detection engine.
GROUND_TRUTH_FIELDS = ["Label", "attack_cat"]

DEFAULT_BATCH_SIZE = 10000


@dataclass
class DatasetBundle:
    """Complete dataset with separate detection and ground-truth data."""

    features: pd.DataFrame
    ground_truth: pd.DataFrame
    total_records: int


@dataclass
class DatasetBatch:
    """A batch of records with original source indexes preserved."""

    features: pd.DataFrame
    ground_truth: pd.DataFrame
    start_record_id: int
    end_record_id: int
    total_records: int


def canonicalise_field_name(name: str) -> str:
    """Normalise dataset feature names."""

    name = str(name).replace("\ufeff", "").strip()
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"_+", "_", name)

    return name.strip("_")


def load_feature_names() -> list[str]:
    """Load and validate the 49 feature names from metadata."""

    if not FEATURES_FILE.exists():
        raise FileNotFoundError(
            f"Feature metadata not found: {FEATURES_FILE}"
        )

    metadata = pd.read_csv(
        FEATURES_FILE,
        encoding="cp1252"
    )

    if "Name" not in metadata.columns:
        raise ValueError(
            "Feature metadata must contain a 'Name' column."
        )

    feature_names = [
        canonicalise_field_name(name)
        for name in metadata["Name"].tolist()
    ]

    if len(feature_names) != 49:
        raise ValueError(
            f"Expected 49 feature names, found {len(feature_names)}."
        )

    if len(set(feature_names)) != len(feature_names):
        raise ValueError("Duplicate feature names detected.")

    missing_ground_truth = [
        field for field in GROUND_TRUTH_FIELDS
        if field not in feature_names
    ]

    if missing_ground_truth:
        raise ValueError(
            "Metadata is missing ground-truth fields: "
            + ", ".join(missing_ground_truth)
        )

    return feature_names


def _validate_dataframe(dataframe: pd.DataFrame) -> None:
    """Validate the structure of a loaded dataset section."""

    if dataframe.shape[1] != 49:
        raise ValueError(
            f"Expected 49 columns, found {dataframe.shape[1]}."
        )

    missing_fields = [
        field for field in GROUND_TRUTH_FIELDS
        if field not in dataframe.columns
    ]

    if missing_fields:
        raise ValueError(
            f"Missing ground-truth fields: {missing_fields}"
        )


def _split_dataframe(
    dataframe: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Separate detection features from evaluation labels."""

    _validate_dataframe(dataframe)

    ground_truth = dataframe[GROUND_TRUTH_FIELDS].copy()

    features = dataframe.drop(
        columns=GROUND_TRUTH_FIELDS
    ).copy()

    return features, ground_truth


def load_dataset() -> DatasetBundle:
    """
    Load the complete UNSW-NB15 dataset.

    This function is retained for analysis and evaluation tasks.
    For production processing, use iter_dataset_batches().
    """

    if not DATASET_FILE.exists():
        raise FileNotFoundError(
            f"Dataset file not found: {DATASET_FILE}"
        )

    feature_names = load_feature_names()

    dataframe = pd.read_csv(
        DATASET_FILE,
        header=None,
        names=feature_names,
        encoding="utf-8-sig",
        low_memory=False
    )

    features, ground_truth = _split_dataframe(dataframe)

    return DatasetBundle(
        features=features,
        ground_truth=ground_truth,
        total_records=len(dataframe)
    )


def count_dataset_records() -> int:
    """
    Count source records without loading all feature columns into memory.
    """

    if not DATASET_FILE.exists():
        raise FileNotFoundError(
            f"Dataset file not found: {DATASET_FILE}"
        )

    feature_names = load_feature_names()

    total_records = 0

    reader = pd.read_csv(
        DATASET_FILE,
        header=None,
        names=feature_names,
        usecols=[0],
        encoding="utf-8-sig",
        chunksize=100000
    )

    for chunk in reader:
        total_records += len(chunk)

    return total_records


def iter_dataset_batches(
    batch_size: int = DEFAULT_BATCH_SIZE
):
    """
    Read UNSW-NB15 in batches.

    Original source record IDs are preserved across batches.
    Ground-truth fields remain separate from detection features.
    """

    if (
        isinstance(batch_size, bool)
        or not isinstance(batch_size, int)
        or batch_size <= 0
    ):
        raise ValueError(
            "Batch size must be a positive integer."
        )

    if not DATASET_FILE.exists():
        raise FileNotFoundError(
            f"Dataset file not found: {DATASET_FILE}"
        )

    feature_names = load_feature_names()

    reader = pd.read_csv(
        DATASET_FILE,
        header=None,
        names=feature_names,
        encoding="utf-8-sig",
        chunksize=batch_size,
        low_memory=False
    )

    record_offset = 0

    for dataframe in reader:

        _validate_dataframe(dataframe)

        batch_length = len(dataframe)

        # Preserve original dataset record IDs.
        original_indexes = range(
            record_offset,
            record_offset + batch_length
        )

        dataframe.index = original_indexes

        features, ground_truth = _split_dataframe(dataframe)

        yield DatasetBatch(
            features=features,
            ground_truth=ground_truth,
            start_record_id=record_offset,
            end_record_id=record_offset + batch_length - 1,
            total_records=batch_length
        )

        record_offset += batch_length


if __name__ == "__main__":
    dataset = load_dataset()

    print("\nUNSW-NB15 Dataset successfully loaded.")
    print(f"Total records: {dataset.total_records}")
    print(f"Detection features: {dataset.features.shape[1]}")
    print(f"Ground-truth fields: {dataset.ground_truth.shape[1]}")

    print("\nDetection feature columns:")
    print(dataset.features.columns.tolist())

    print("\nGround-truth columns:")
    print(dataset.ground_truth.columns.tolist())

    print("\nFirst five records:")
    print(dataset.features.head())
