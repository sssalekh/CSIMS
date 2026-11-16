"""Unit tests for the five CSIMS detection rules."""

import unittest

import pandas as pd

from detection.config import (
    DETECTION_THRESHOLDS,
    INITIAL_DETECTION_THRESHOLDS,
)
from detection.engine import DetectionEngine
from detection.rules import build_detection_rules


def make_record(**values):
    """Return one ordinary, non-suspicious record with optional changes."""
    record = {
        "proto": "tcp",
        "state": "FIN",
        "service": "http",
        "Sload": 50000.0,
        "sbytes": 1500,
        "dbytes": 9000,
        "tcprtt": 0.001,
    }
    record.update(values)
    return record


class TestDetectionRules(unittest.TestCase):
    def setUp(self):
        self.thresholds = dict(DETECTION_THRESHOLDS)
        self.rules = {
            rule.rule_id: rule
            for rule in build_detection_rules(self.thresholds)
        }

    def matches(self, rule_id, **values):
        frame = pd.DataFrame([make_record(**values)])
        result = self.rules[rule_id].condition(frame)
        return bool(result.fillna(False).astype(bool).iloc[0])

    def test_five_rules_with_expected_identifiers(self):
        self.assertEqual(
            list(self.rules),
            ["DOS-001", "REC-001", "EXP-001", "GEN-001", "CON-001"],
        )

    def test_rules_are_accepted_by_detection_engine(self):
        DetectionEngine(list(self.rules.values()))
        DetectionEngine(build_detection_rules(INITIAL_DETECTION_THRESHOLDS))

    def test_ordinary_record_matches_no_rule(self):
        for rule_id in self.rules:
            self.assertFalse(self.matches(rule_id), rule_id)

    def test_dos_rule_uses_source_load_threshold(self):
        limit = self.thresholds["dos_sload"]
        self.assertTrue(self.matches("DOS-001", Sload=limit))
        self.assertFalse(self.matches("DOS-001", Sload=limit - 1))

    def test_rec_rule_requires_unanswered_non_dns_attempt(self):
        self.assertTrue(
            self.matches("REC-001", state="INT", dbytes=0, service="-")
        )
        self.assertFalse(
            self.matches("REC-001", state="INT", dbytes=500, service="-")
        )
        self.assertFalse(
            self.matches("REC-001", state="FIN", dbytes=0, service="-")
        )
        self.assertFalse(
            self.matches("REC-001", state="INT", dbytes=0, service="dns")
        )

    def test_exp_rule_requires_slow_tcp_handshake(self):
        limit = self.thresholds["exp_tcprtt"]
        self.assertTrue(self.matches("EXP-001", tcprtt=limit))
        self.assertFalse(self.matches("EXP-001", tcprtt=limit / 2))
        self.assertFalse(
            self.matches("EXP-001", proto="udp", tcprtt=limit * 10)
        )

    def test_gen_rule_detects_non_standard_protocol(self):
        self.assertTrue(self.matches("GEN-001", proto="sctp"))
        self.assertFalse(self.matches("GEN-001", proto="udp"))
        self.assertFalse(self.matches("GEN-001", proto=None))

    def test_con_rule_detects_short_unanswered_dns_request(self):
        limit = self.thresholds["con_dns_max_sbytes"]
        self.assertTrue(
            self.matches(
                "CON-001", service="dns", state="INT", sbytes=limit
            )
        )
        self.assertFalse(
            self.matches(
                "CON-001", service="dns", state="INT", sbytes=limit + 1
            )
        )
        self.assertFalse(
            self.matches(
                "CON-001", service="dns", state="CON", sbytes=limit
            )
        )

    def test_nominal_values_are_case_and_space_insensitive(self):
        self.assertTrue(
            self.matches("REC-001", state=" int ", dbytes=0, service="-")
        )
        self.assertTrue(self.matches("GEN-001", proto=" SCTP "))

    def test_invalid_numeric_value_does_not_match(self):
        self.assertFalse(self.matches("DOS-001", Sload="not-a-number"))

    def test_missing_threshold_is_rejected(self):
        thresholds = dict(self.thresholds)
        del thresholds["exp_tcprtt"]
        with self.assertRaises(ValueError):
            build_detection_rules(thresholds)

    def test_negative_or_boolean_threshold_is_rejected(self):
        for value in (-1, True, float("nan")):
            thresholds = dict(self.thresholds)
            thresholds["dos_sload"] = value
            with self.assertRaises(ValueError):
                build_detection_rules(thresholds)

    def test_rules_do_not_require_ground_truth_or_host_identifiers(self):
        excluded = {
            "Label", "attack_cat", "srcip", "dstip", "sport", "dsport",
            "sttl", "dttl", "ct_state_ttl", "Stime", "Ltime",
        }
        for rule in self.rules.values():
            self.assertFalse(
                excluded.intersection(rule.required_features),
                rule.rule_id,
            )

    def test_record_matching_several_rules_creates_one_incident(self):
        frame = pd.DataFrame([
            make_record(
                proto="sctp",
                Sload=self.thresholds["dos_sload"] * 2,
            )
        ])
        incidents = DetectionEngine(
            list(self.rules.values())
        ).evaluate(frame)

        self.assertEqual(len(incidents), 1)
        self.assertCountEqual(
            incidents.iloc[0]["matched_rule_ids"], ["DOS-001", "GEN-001"]
        )
        self.assertEqual(incidents.iloc[0]["severity"], "High")


if __name__ == "__main__":
    unittest.main()
