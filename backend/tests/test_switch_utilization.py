from app.services.switch_utilization import SwitchUtilizationTracker


def topology(state="connected"):
    return {
        "switches": [
            {
                "switch_id": "s1",
                "dpid": "0000000000000001",
                "state": state,
            },
        ],
    }


def stats(timestamp, ports):
    return {
        "updated_at": timestamp,
        "switches": [{"switch_id": "s1", "ports": ports}],
    }


def port(port_no, rx_bytes, tx_bytes):
    return {
        "port_no": port_no,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
    }


def test_counter_delta_becomes_busiest_port_utilization():
    tracker = SwitchUtilizationTracker(capacity_bps=10_000_000)

    first = tracker.update(
        stats(
            "2026-07-21T00:00:00+00:00",
            [
                port(1, 100, 100),
                port(2, 100, 100),
                port(0xFFFFFFFE, 0, 9_000_000),
            ],
        ),
        topology(),
    )
    second = tracker.update(
        stats(
            "2026-07-21T00:00:05+00:00",
            [
                port(1, 625_100, 100),
                port(2, 100, 1_250_100),
                port(0xFFFFFFFE, 0, 99_000_000),
            ],
        ),
        topology(),
    )

    assert first[0]["sampled"] is False
    assert first[0]["status"] == "sampling"
    assert second[0]["sampled"] is True
    assert second[0]["rx_bps"] == 1_000_000
    assert second[0]["tx_bps"] == 2_000_000
    assert second[0]["bps"] == 2_000_000
    assert second[0]["utilization"] == 20.0
    assert second[0]["sample_interval_seconds"] == 5.0
    assert second[0]["status"] == "normal"


def test_short_duplicate_snapshot_keeps_last_calculated_usage():
    tracker = SwitchUtilizationTracker(capacity_bps=10_000_000)
    tracker.update(
        stats("2026-07-21T00:00:00+00:00", [port(1, 0, 0)]),
        topology(),
    )
    sampled = tracker.update(
        stats(
            "2026-07-21T00:00:05+00:00",
            [port(1, 4_500_000, 0)],
        ),
        topology(),
    )
    duplicate = tracker.update(
        stats(
            "2026-07-21T00:00:05.100000+00:00",
            [port(1, 4_500_000, 0)],
        ),
        topology(),
    )

    assert sampled[0]["utilization"] == 72.0
    assert sampled[0]["status"] == "warning"
    assert duplicate[0]["utilization"] == 72.0
    assert duplicate[0]["status"] == "warning"


def test_disconnected_switch_has_explicit_status():
    tracker = SwitchUtilizationTracker(capacity_bps=10_000_000)
    tracker.update(
        stats("2026-07-21T00:00:00+00:00", [port(1, 0, 0)]),
        topology(),
    )
    tracker.update(
        stats("2026-07-21T00:00:05+00:00", [port(1, 625_000, 0)]),
        topology(),
    )
    result = tracker.update(
        stats("2026-07-21T00:00:10+00:00", [port(1, 625_000, 0)]),
        topology(state="disconnected"),
    )

    assert result[0]["state"] == "disconnected"
    assert result[0]["status"] == "disconnected"
    assert result[0]["bps"] == 0.0
    assert result[0]["utilization"] == 0.0
