NUM_FEATURES = [
    "honeypot_count",
    "destination_port_count",
    "days_seen_count",
    "active_days_ratio",
    "login_attempts",
    "login_attempts_per_day",
    "interaction_count",
    "std_days_between",
    "days_since_last_seen",
    "days_since_first_seen",
]

CATEGORICAL_FEATURES = [
    "asn",
    "ip_reputation",
]

MULTI_VAL_FEATURES = [
    "honeypots",
]

SAMPLE_COUNT = 100
