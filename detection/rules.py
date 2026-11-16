
import math
from numbers import Real

from detection.engine import DetectionRule


def build_detection_rules(
    thresholds: dict
) -> list[DetectionRule]:
    """
    Build deterministic detection rules using configured thresholds.

    Dataset ground-truth fields (Label and attack_cat)
    are not used by the detection rules.

    Initial incident categories and severity follow
    Table 4 of the thesis.
    """

    required_thresholds = {
        "dos_sload",
        "dos_spkts",
        "rec_ct_dst_src_ltm",
        "exp_trans_depth",
        "exp_http_methods",
        "gen_sbytes",
        "con_ct_srv_src",
        "con_ct_src_ltm"
    }

    if not isinstance(thresholds, dict):
        raise TypeError(
            "Thresholds must be provided as a dictionary."
        )

    missing = required_thresholds - thresholds.keys()

    if missing:
        raise ValueError(
            "Missing detection thresholds: "
            + ", ".join(sorted(missing))
        )

    for name in required_thresholds:

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

    rules = [

        # DOS / DDoS
        # Initial severity: High
        DetectionRule(
            rule_id="DOS-001",
            name="High network traffic",
            description=(
                "Detects records with unusually high source traffic "
                "or packet volume."
            ),
            severity="High",
            category="Dos / DDoS",
            required_features=(
                "Sload",
                "Spkts"
            ),
            condition=lambda df: (
                (df["Sload"] >= thresholds["dos_sload"])
                |
                (df["Spkts"] >= thresholds["dos_spkts"])
            )
        ),

        # Reconnaissance
        # Initial severity: Low
        DetectionRule(
            rule_id="REC-001",
            name="Repeated communication pattern",
            description=(
                "Detects unusually frequent communication patterns "
                "between source and destination."
            ),
            severity="Low",
            category="Reconnaissance",
            required_features=(
                "ct_dst_src_ltm",
            ),
            condition=lambda df: (
                df["ct_dst_src_ltm"]
                >= thresholds["rec_ct_dst_src_ltm"]
            )
        ),

        # Exploitation
        # Initial severity: Critical
        DetectionRule(
            rule_id="EXP-001",
            name="Unusual application-level activity",
            description=(
                "Detects records with elevated HTTP transaction depth "
                "and HTTP method activity."
            ),
            severity="Critical",
            category="Exploitation",
            required_features=(
                "trans_depth",
                "ct_flw_http_mthd"
            ),
            condition=lambda df: (
                (df["trans_depth"] >= thresholds["exp_trans_depth"])
                &
                (
                    df["ct_flw_http_mthd"]
                    >= thresholds["exp_http_methods"]
                )
            )
        ),

        # Other suspicious activity
        # Initial severity: Medium
        DetectionRule(
            rule_id="GEN-001",
            name="High data transfer volume",
            description=(
                "Detects records with unusually high source byte volume."
            ),
            severity="Medium",
            category="Other suspicious activity",
            required_features=(
                "sbytes",
            ),
            condition=lambda df: (
                df["sbytes"] >= thresholds["gen_sbytes"]
            )
        ),

        # Other suspicious activity
        # Initial severity: Medium
        DetectionRule(
            rule_id="CON-001",
            name="High connection frequency",
            description=(
                "Detects unusually frequent connections from "
                "the same source."
            ),
            severity="Medium",
            category="Other suspicious activity",
            required_features=(
                "ct_srv_src",
                "ct_src_ltm"
            ),
            condition=lambda df: (
                (
                    df["ct_srv_src"]
                    >= thresholds["con_ct_srv_src"]
                )
                &
                (
                    df["ct_src_ltm"]
                    >= thresholds["con_ct_src_ltm"]
                )
            )
        )
    ]

    return rules
