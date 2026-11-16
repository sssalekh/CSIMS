
import time

from dataset.loader import (
    DATASET_FILE,
    DEFAULT_BATCH_SIZE,
    count_dataset_records,
    iter_dataset_batches
)

from detection.engine import DetectionEngine
from detection.rules import build_detection_rules
from detection.config import DETECTION_THRESHOLDS

from storage.db import (
    initialize_database,
    register_detection_rules,
    get_enabled_rule_ids,
    get_detection_rule_database_ids,
    get_connection,
    save_detection_results,
)


# How often (in seconds) enabled/disabled rule states are reloaded
# from the database while the dataset is being processed.
RULE_REFRESH_INTERVAL = 1.0


def process_dataset(
    batch_size=DEFAULT_BATCH_SIZE,
    max_records=None
):
    """
    Process the UNSW-NB15 dataset and save detected
    incidents to the database.

    max_records limits the number of source records
    processed during one run.
    """

    # 1. Validate input parameters.
    if (
        isinstance(batch_size, bool)
        or not isinstance(batch_size, int)
        or batch_size <= 0
    ):
        raise ValueError("Batch size must be a positive integer.")

    if max_records is not None:
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or max_records <= 0
        ):
            raise ValueError("Maximum records must be a positive integer.")

    # 2. Check the dataset file.
    if not DATASET_FILE.exists():
        raise FileNotFoundError(
            f"Dataset file not found: {DATASET_FILE}"
        )

    # 3. Initialize the database.
    initialize_database()

    # 4. Build and register detection rules.
    rules = build_detection_rules(DETECTION_THRESHOLDS)
    register_detection_rules(rules)

    # 5. Get enabled rules.
    enabled_rule_ids = get_enabled_rule_ids(rules)

    for rule in rules:
        rule.enabled = rule.rule_id in enabled_rule_ids

    # 6. Initialize the Detection Engine.
    detection_engine = DetectionEngine(rules)

    # Resolve database rule IDs once for this processing run.
    rule_database_ids = get_detection_rule_database_ids(rules)

    # 7. Count source records.
    available_records = count_dataset_records()

    if max_records is None:
        total_records = available_records
    else:
        total_records = min(max_records, available_records)

    if total_records == 0:
        raise ValueError("The dataset contains no records.")

    processed_records = 0
    detected_incidents = 0
    database_connection = None
    # Rule states were loaded above, immediately before processing starts.
    last_rule_refresh = time.monotonic()

    try:
        # Keep one SQLite connection open for this processing run.
        # Each detected incident is still committed immediately.
        database_connection = get_connection()

        # 9. Read the dataset in batches, but evaluate each source
        # record individually. This allows every detected incident
        # to be committed before the next source record is evaluated.
        for batch in iter_dataset_batches(batch_size):

            remaining_records = total_records - processed_records

            if remaining_records <= 0:
                break

            features = batch.features.iloc[:remaining_records]

            for position in range(len(features)):
                # keep the original dataset for traceability
                record = features.iloc[[position]]
                
                # Refresh rule states from the database at most once per
                # RULE_REFRESH_INTERVAL seconds instead of for every record.
                # A rule disabled in the meantime still cannot create an
                # incident: save_detection_results rechecks rule states
                # inside its write transaction.
                now = time.monotonic()
                if now - last_rule_refresh >= RULE_REFRESH_INTERVAL:
                    enabled_rule_ids = get_enabled_rule_ids(
                        rules,
                        connection=database_connection
                    )

                    for rule in rules:
                        rule.enabled = rule.rule_id in enabled_rule_ids

                    last_rule_refresh = now

                # ground truth labels are never passed to the engine
                incidents = detection_engine.evaluate(record)

                # only actual detections are written to database
                if not incidents.empty:
                    new_incidents = save_detection_results(
                        incidents=incidents,
                        records=record,
                        rules=rules,
                        rule_database_ids=rule_database_ids,
                        connection=database_connection
                    )
                    detected_incidents += new_incidents

                processed_records += 1

        # 10. Verify the number of processed records.
        if processed_records != total_records:
            raise RuntimeError(
                f"Expected {total_records} records, "
                f"but processed {processed_records}."
            )

        # Save processing state only after the full dataset has been processed successfully.
        if max_records is None:
            dataset_stat = DATASET_FILE.stat()
            state_file = (
                DATASET_FILE.resolve().parent.parent
                / ".dataset_processed"
            )

            state_file.write_text(
                f"{dataset_stat.st_size}:{dataset_stat.st_mtime_ns}",
                encoding="utf-8"
            )
            
        return {
            "dataset_name": "UNSW-NB15",
            "total_records": total_records,
            "processed_records": processed_records,
            "detected_incidents": detected_incidents,
            "enabled_rules": sorted(enabled_rule_ids),
            "status": "Completed"
        }

    finally:
        if database_connection is not None:
            database_connection.close()
