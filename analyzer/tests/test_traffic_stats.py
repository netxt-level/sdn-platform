from analyzer.app.detection.traffic_stats import TrafficStatsBuilder


def test_warning_starts_at_1500_pps():
    builder = TrafficStatsBuilder()

    below_threshold = builder.build_traffic_stats(
        {
            "window_sec": 1,
            "total_packets": 1499,
            "total_bits": 0,
        }
    )
    at_threshold = builder.build_traffic_stats(
        {
            "window_sec": 1,
            "total_packets": 1500,
            "total_bits": 0,
        }
    )

    assert below_threshold["network_status"] == "normal"
    assert at_threshold["network_status"] == "warning"


def test_bps_thresholds_start_at_10_and_20_mbps():
    builder = TrafficStatsBuilder()

    below_warning = builder.build_traffic_stats(
        {
            "window_sec": 1,
            "total_packets": 0,
            "total_bits": 9_999_999,
        }
    )
    at_warning = builder.build_traffic_stats(
        {
            "window_sec": 1,
            "total_packets": 0,
            "total_bits": 10_000_000,
        }
    )
    at_critical = builder.build_traffic_stats(
        {
            "window_sec": 1,
            "total_packets": 0,
            "total_bits": 20_000_000,
        }
    )

    assert below_warning["network_status"] == "normal"
    assert at_warning["network_status"] == "warning"
    assert at_critical["network_status"] == "critical"
