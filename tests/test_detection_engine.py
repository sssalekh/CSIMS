"""Unit tests for the category-aware CSIMS detection engine."""

import unittest

import pandas as pd

from detection.engine import DetectionEngine, DetectionRule


class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
        # The original DataFrame index represents the source record ID.
        self.records = pd.DataFrame(
            {
                "dur": [0.1, 10.0, 0.5],
                "sbytes": [100, 500000, 200],
                "dbytes": [100, 1000, 200],
            },
            index=[0, 1, 2],
        )

        self.rules = [
            DetectionRule(
                rule_id="TEST-DOS-001",
                name="High traffic volume",
                description="Detects records with high source bytes.",
                severity="High",
                category="Dos / DDoS",
                condition=lambda frame: frame["sbytes"] > 100000,
                required_features=("sbytes",),
            ),
            DetectionRule(
                rule_id="TEST-REC-001",
                name="Long connection pattern",
                description="Detects unusually long connections.",
                severity="Low",
                category="Reconnaissance",
                condition=lambda frame: frame["dur"] > 5,
                required_features=("dur",),
            ),
        ]
        self.engine = DetectionEngine(self.rules)

    def test_detects_matching_records(self):
        result = self.engine.evaluate(self.records)

        self.assertEqual(len(result), 1)
        self.assertEqual(int(result.iloc[0]["source_record_id"]), 1)

    def test_multiple_rules_create_one_incident(self):
        result = self.engine.evaluate(self.records)

        self.assertEqual(len(result), 1)
        self.assertCountEqual(
            result.iloc[0]["matched_rule_ids"],
            ["TEST-DOS-001", "TEST-REC-001"],
        )

    def test_highest_severity_is_selected(self):
        result = self.engine.evaluate(self.records)

        self.assertEqual(result.iloc[0]["severity"], "High")
        self.assertEqual(result.iloc[0]["category"], "Dos / DDoS")

    def test_disabled_rule_is_not_applied(self):
        self.rules[0].enabled = False
        result = DetectionEngine(self.rules).evaluate(self.records)

        self.assertEqual(len(result), 1)
        self.assertEqual(result.iloc[0]["severity"], "Low")
        self.assertEqual(result.iloc[0]["category"], "Reconnaissance")
        self.assertEqual(
            result.iloc[0]["matched_rule_ids"], ["TEST-REC-001"]
        )

    def test_no_matches_returns_empty_dataframe_with_expected_columns(self):
        records = pd.DataFrame(
            {
                "dur": [0.1, 0.2],
                "sbytes": [100, 200],
                "dbytes": [100, 200],
            },
            index=[10, 11],
        )

        result = self.engine.evaluate(records)

        self.assertTrue(result.empty)
        self.assertEqual(
            list(result.columns),
            [
                "source_record_id",
                "category",
                "severity",
                "matched_rule_ids",
            ],
        )

    def test_source_record_indexes_are_preserved(self):
        records = self.records.copy()
        records.index = [100, 200, 300]

        result = self.engine.evaluate(records)

        self.assertEqual(int(result.iloc[0]["source_record_id"]), 200)

    def test_ground_truth_fields_are_rejected(self):
        records = self.records.copy()
        records["Label"] = [0, 1, 0]

        with self.assertRaises(ValueError):
            self.engine.evaluate(records)

    def test_duplicate_rule_ids_are_rejected(self):
        duplicate_rules = [
            self.rules[0],
            DetectionRule(
                rule_id="TEST-DOS-001",
                name="Duplicate rule",
                description="A rule with a duplicate identifier.",
                severity="Medium",
                category="Other suspicious activity",
                condition=lambda frame: frame["dur"] > 1,
                required_features=("dur",),
            ),
        ]

        with self.assertRaises(ValueError):
            DetectionEngine(duplicate_rules)

    def test_missing_required_feature_is_rejected(self):
        records = self.records.drop(columns=["sbytes"])

        with self.assertRaises(ValueError):
            self.engine.evaluate(records)


if __name__ == "__main__":
    unittest.main()
