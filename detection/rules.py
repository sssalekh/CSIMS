import math
from numbers import Real

import pandas as pd

from detection.config import STANDARD_PROTOCOLS
from detection.engine import DetectionRule


REQUIRED_THRESHOLDS = (
    "dos_sload",
    "rec_max_dbytes",
    "exp_tcprtt",
    "con_dns_max_sbytes",
)


def _number(df: pd.DataFrame, column: str) -> pd.Series:
    """Return a numeric feature; non-numeric values become missing."""
    return pd.to_numeric(df[column], errors="coerce")


def _normalise_text(value):
    if isinstance(value, str):
        return value.strip().lower()
    return None


def _text(df: pd.DataFrame, column: str) -> pd.Series:
    """
    Return a nominal feature in lower case without extra whitespace.

    Missing and non-text values become None and therefore never match.
    A plain element-wise conversion is used because the application
    evaluates records one at a time, where it is faster than the pandas
    string accessor.
    """
    return df[column].map(_normalise_text)


def _validate_thresholds(thresholds: dict) -> None:
    if not isinstance(thresholds, dict):
        raise TypeError(
            "Thresholds must be provided as a dictionary."
        )

    missing = set(REQUIRED_THRESHOLDS) - thresholds.keys()

    if missing:
        raise ValueError(
            "Missing detection thresholds: "
            + ", ".join(sorted(missing))
        )

    for name in REQUIRED_THRESHOLDS:
        value = thresholds[name]

        if (
            isinstance(value, bool)
            or not isinstance(value, Real)
            or not math.isfinite(float(value))
            or value < 0
        ):
            raise ValueError(
                f"Threshold '{name}' must be a finite "
                "non-negative number."
            )


def build_detection_rules(
    thresholds: dict,
    standard_protocols=STANDARD_PROTOCOLS,
) -> list[DetectionRule]:
    """
    Build deterministic detection rules using configured thresholds.

    Each rule describes an observable network behaviour. Dataset
    ground-truth fields (Label and attack_cat) are never used. Features
    that only identify the test-bed hosts (IP addresses, ports, TTL values
    and timestamps) are deliberately not used either.

    Initial incident categories and severity follow Table 4 of the thesis.
    """

    _validate_thresholds(thresholds)
    standard_protocols = frozenset(
        str(protocol).strip().lower() for protocol in standard_protocols
    )

    rules = [

        # DOS / DDoS
        # Initial severity: High
        DetectionRule(
            rule_id="DOS-001",
            name="High network traffic",
            description=(
                "Detects flows whose source sends traffic at an unusually "
                "high rate (source load in bits per second)."
            ),
            severity="High",
            category="Dos / DDoS",
            required_features=(
                "Sload",
            ),
            condition=lambda df: (
                _number(df, "Sload") >= thresholds["dos_sload"]
            )
        ),

        # Reconnaissance
        # Initial severity: Low
        DetectionRule(
            rule_id="REC-001",
            name="Unanswered connection attempt",
            description=(
                "Detects non-DNS connection attempts that were not "
                "completed and received no data from the destination, "
                "which is typical of scanning and probing."
            ),
            severity="Low",
            category="Reconnaissance",
            required_features=(
                "state",
                "dbytes",
                "service",
                "proto",
            ),
            condition=lambda df: (
                (_text(df, "state") == "int")
                & (_number(df, "dbytes") <= thresholds["rec_max_dbytes"])
                & (_text(df, "service") != "dns")
                & (_text(df, "proto") != "arp")
            )
        ),

        # Exploitation
        # Initial severity: Critical
        DetectionRule(
            rule_id="EXP-001",
            name="Abnormal TCP handshake delay",
            description=(
                "Detects TCP connections whose set-up round-trip time is "
                "unusually long, which may indicate exploitation tools or "
                "malformed traffic interacting with the target service."
            ),
            severity="Critical",
            category="Exploitation",
            required_features=(
                "proto",
                "tcprtt",
            ),
            condition=lambda df: (
                (_text(df, "proto") == "tcp")
                & (_number(df, "tcprtt") >= thresholds["exp_tcprtt"])
            )
        ),

        # Other suspicious activity
        # Initial severity: Medium
        DetectionRule(
            rule_id="GEN-001",
            name="Non-standard network protocol",
            description=(
                "Detects traffic that uses a network protocol not "
                "expected in an ordinary small-business network."
            ),
            severity="Medium",
            category="Other suspicious activity",
            required_features=(
                "proto",
            ),
            condition=lambda df: (
                _text(df, "proto").map(
                    lambda value: (
                        value is not None
                        and value not in standard_protocols
                    )
                ).astype(bool)
            )
        ),

        # Other suspicious activity
        # Initial severity: Medium
        DetectionRule(
            rule_id="CON-001",
            name="Unanswered short DNS request",
            description=(
                "Detects short DNS requests that received no response, "
                "which may indicate automated DNS probing or abuse."
            ),
            severity="Medium",
            category="Other suspicious activity",
            required_features=(
                "service",
                "state",
                "sbytes",
            ),
            condition=lambda df: (
                (_text(df, "service") == "dns")
                & (_text(df, "state") == "int")
                & (
                    _number(df, "sbytes")
                    <= thresholds["con_dns_max_sbytes"]
                )
            )
        )
    ]

    return rules