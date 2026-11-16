
"""
Initial detection configuration.

Thresholds are preliminary values based on UNSW-NB15
feature distributions. They require further experimental
evaluation and justification.
"""

DETECTION_THRESHOLDS = {
    "dos_sload": 132000000,
    "dos_spkts": 426,
    "rec_ct_dst_src_ltm": 11,
    "exp_trans_depth": 2,
    "exp_http_methods": 6,
    "gen_sbytes": 37500,
    "con_ct_srv_src": 23,
    "con_ct_src_ltm": 23
}
