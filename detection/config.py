"""
Detection configuration of the CSIMS rule-based Detection Engine.

INITIAL_DETECTION_THRESHOLDS
    Starting values chosen from general network-traffic knowledge before
    any experiment (for example, 10 Mbit/s for a high source load).
    They are the "initial configuration" in the evaluation.

DETECTION_THRESHOLDS
    Values used by the application. They were selected experimentally with
    dataset/calibrate_rules.py: candidates come from the Calibration split,
    the selection is made on the Validation split and the Test split is used
    only for the final evaluation. See dataset/calibration_results/.

STANDARD_PROTOCOLS
    Transport and network protocols that are expected in an ordinary
    small-business network. Any other protocol is reported by GEN-001.
"""

INITIAL_DETECTION_THRESHOLDS = {
    # DOS-001: minimum source load (bits per second).
    "dos_sload": 10000000,
    # REC-001: maximum bytes returned by the destination.
    "rec_max_dbytes": 0,
    # EXP-001: minimum TCP connection set-up round-trip time (seconds).
    "exp_tcprtt": 0.05,
    # CON-001: maximum size of an unanswered DNS request (bytes).
    "con_dns_max_sbytes": 100,
}

# Selected by dataset/calibrate_rules.py --seed 2026
# (dataset/calibration_results/proposed_thresholds.json).
DETECTION_THRESHOLDS = {
    "dos_sload": 132000000,
    "rec_max_dbytes": 0,
    "exp_tcprtt": 0.01116288,
    "con_dns_max_sbytes": 114,
}

STANDARD_PROTOCOLS = frozenset({
    "tcp",
    "udp",
    "icmp",
    "arp",
    "igmp",
    "ospf",
})