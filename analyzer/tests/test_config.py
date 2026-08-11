from unittest.mock import patch

from analyzer.app.config import load_config


def test_server_behavior_config_defaults():
    with patch.dict("os.environ", {}, clear=True):
        config = load_config()

    assert config.protected_server_ips == ("10.0.0.100",)
    assert config.server_egress_allowlist == ()
    assert config.lateral_fanout_unique_dst_threshold == 2
    assert config.exfil_outbound_bps_threshold == 1_000_000
    assert config.c2_beacon_min_connections == 6
    assert config.c2_beacon_max_jitter_ratio == 0.2


def test_server_behavior_config_parses_lists_and_thresholds():
    with patch.dict(
        "os.environ",
        {
            "PROTECTED_SERVER_IPS": "10.0.0.100, 10.0.0.200",
            "SERVER_EGRESS_ALLOWLIST": "10.0.0.53,10.0.0.10",
            "LATERAL_FANOUT_UNIQUE_DST_THRESHOLD": "3",
            "EXFIL_OUTBOUND_BPS_THRESHOLD": "250000",
            "C2_BEACON_MAX_JITTER_RATIO": "0.15",
        },
        clear=True,
    ):
        config = load_config()

    assert config.protected_server_ips == ("10.0.0.100", "10.0.0.200")
    assert config.server_egress_allowlist == ("10.0.0.53", "10.0.0.10")
    assert config.lateral_fanout_unique_dst_threshold == 3
    assert config.exfil_outbound_bps_threshold == 250_000
    assert config.c2_beacon_max_jitter_ratio == 0.15


def test_server_behavior_config_rejects_invalid_values():
    invalid_values = [
        (
            "PROTECTED_SERVER_IPS",
            "",
            "PROTECTED_SERVER_IPS must contain at least one IP",
        ),
        (
            "C2_BEACON_MAX_JITTER_RATIO",
            "1.5",
            "C2_BEACON_MAX_JITTER_RATIO must be between 0 and 1",
        ),
    ]

    for name, value, message in invalid_values:
        with patch.dict("os.environ", {name: value}, clear=True):
            try:
                load_config()
            except RuntimeError as exc:
                assert message in str(exc)
            else:
                raise AssertionError(f"{name}={value!r} was accepted")
