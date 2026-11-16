
from dataclasses import dataclass
from typing import Callable

import pandas as pd


SEVERITY_PRIORITY = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}

CATEGORY_INITIAL_SEVERITY = {
    "Reconnaissance": "Low",
    "Dos / DDoS": "High",
    "Exploitation": "Critical",
    "Other suspicious activity": "Medium"
}

FORBIDDEN_GROUND_TRUTH_FIELDS = {
    "Label",
    "attack_cat"
}


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str
    severity: str
    condition: Callable[[pd.DataFrame], pd.Series]
    required_features: tuple = ()
    enabled: bool = True
    category: str = "Other suspicious activity"


class DetectionEngine:
    """
    Rule-based cybersecurity incident detection engine.

    Each source record can produce at most one incident.
    All matching enabled rules are associated with that incident.

    Ground-truth dataset labels are never used for detection.
    """

    def __init__(self, rules: list[DetectionRule]):
        self.rules = list(rules)

        rule_ids = [rule.rule_id for rule in self.rules]

        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("Detection rule IDs must be unique.")

        for rule in self.rules:

            if not rule.rule_id or not rule.rule_id.strip():
                raise ValueError("Detection rule ID cannot be empty.")

            if not rule.name or not rule.name.strip():
                raise ValueError(
                    f"Rule {rule.rule_id} must have a name."
                )

            if rule.severity not in SEVERITY_PRIORITY:
                raise ValueError(
                    f"Invalid severity in rule {rule.rule_id}."
                )

            if rule.category not in CATEGORY_INITIAL_SEVERITY:
                raise ValueError(
                    f"Invalid category in rule {rule.rule_id}."
                )

            expected_severity = CATEGORY_INITIAL_SEVERITY[
                rule.category
            ]

            if rule.severity != expected_severity:
                raise ValueError(
                    f"Rule {rule.rule_id} has severity "
                    f"'{rule.severity}', but category "
                    f"'{rule.category}' requires initial severity "
                    f"'{expected_severity}'."
                )

            if not callable(rule.condition):
                raise TypeError(
                    f"Rule {rule.rule_id} must have a callable condition."
                )

            if not isinstance(rule.required_features, tuple):
                raise TypeError(
                    f"Rule {rule.rule_id} required_features "
                    "must be a tuple."
                )

    def evaluate(self, records: pd.DataFrame) -> pd.DataFrame:
        """
        Evaluate dataset records against enabled detection rules.

        Returns one incident per matching source record, including:
        - source_record_id
        - category
        - severity
        - matched_rule_ids
        """

        if not isinstance(records, pd.DataFrame):
            raise TypeError(
                "Input records must be a pandas DataFrame."
            )

        if not records.columns.is_unique:
            raise ValueError(
                "Input records contain duplicate column names."
            )

        forbidden_fields = (
            FORBIDDEN_GROUND_TRUTH_FIELDS.intersection(
                records.columns
            )
        )

        if forbidden_fields:
            raise ValueError(
                "Ground-truth fields must not be passed "
                "to Detection Engine: "
                + ", ".join(sorted(forbidden_fields))
            )

        if not records.index.is_unique:
            raise ValueError(
                "Source record indexes must be unique."
            )

        active_rules = [
            rule for rule in self.rules
            if rule.enabled
        ]

        # Validate all required features before evaluating records.
        for rule in active_rules:

            missing_features = [
                feature
                for feature in rule.required_features
                if feature not in records.columns
            ]

            if missing_features:
                raise ValueError(
                    f"Rule {rule.rule_id} requires missing features: "
                    + ", ".join(missing_features)
                )

        # Collect all matching rules for every source record.
        matches = {}

        for rule in active_rules:

            result = rule.condition(records)

            if not isinstance(result, pd.Series):
                raise TypeError(
                    f"Rule {rule.rule_id} must return a pandas Series."
                )

            if not result.index.equals(records.index):
                raise ValueError(
                    f"Rule {rule.rule_id} returned an invalid index."
                )

            result = result.fillna(False).astype(bool)

            for source_record_id in records.index[result]:

                matches.setdefault(
                    source_record_id, []
                ).append(rule)

        incidents = []

        # Iterate using the original dataset order.
        # This keeps detection output deterministic.
        for source_record_id in records.index:

            matched_rules = matches.get(source_record_id)

            if not matched_rules:
                continue

            # The rule with the highest severity determines
            # the incident's category and initial severity.
            # Ties are resolved by the configured rule order.
            highest_priority_rule = max(
                matched_rules,
                key=lambda rule: SEVERITY_PRIORITY[
                    rule.severity
                ]
            )

            incidents.append({
                "source_record_id": source_record_id,
                "category": highest_priority_rule.category,
                "severity": highest_priority_rule.severity,
                "matched_rule_ids": [
                    rule.rule_id for rule in matched_rules
                ]
            })

        return pd.DataFrame(
            incidents,
            columns=[
                "source_record_id",
                "category",
                "severity",
                "matched_rule_ids"
            ]
        )
