from datetime import datetime
from datetime import timezone

from analyzer.app.detection.security_events import SecurityEventBuilder
from analyzer.app.detection.server_behavior import ServerBehaviorDetector


NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)


def tcp_packet(
    *,
    src_ip="10.0.0.100",
    dst_ip="10.0.0.3",
    src_port=40000,
    dst_port=4444,
    flags="S",
    timestamp=None,
    packet_size=60,
):
    return {
        "timestamp": timestamp if timestamp is not None else NOW.timestamp(),
        "packet_size": packet_size,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": "TCP",
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": flags,
    }


def test_detects_protected_server_role_violation():
    detector = ServerBehaviorDetector()

    alerts = detector.detect([tcp_packet()], now=NOW)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["attack_type"] == "SERVER_EGRESS"
    assert alert["src_ip"] == "10.0.0.100"
    assert alert["dst_ip"] == "10.0.0.3"
    assert alert["detection_rule"] == "protected_server_tcp_egress"
    assert alert["evidence"]["dst_ports"] == [4444]


def test_ignores_normal_syn_ack_response():
    detector = ServerBehaviorDetector()

    alerts = detector.detect([tcp_packet(flags="SA")], now=NOW)

    assert alerts == []


def test_ignores_non_server_source_and_allowlisted_destination():
    detector = ServerBehaviorDetector(
        egress_allowlist={"10.0.0.2"},
    )

    alerts = detector.detect(
        [
            tcp_packet(src_ip="10.0.0.1"),
            tcp_packet(dst_ip="10.0.0.2"),
        ],
        now=NOW,
    )

    assert alerts == []


def test_suppresses_syn_retransmission_for_same_flow():
    detector = ServerBehaviorDetector()
    first = tcp_packet()
    retransmission = tcp_packet(timestamp=NOW.timestamp() + 1)

    first_alerts = detector.detect([first], now=NOW)
    second_alerts = detector.detect(
        [retransmission],
        now=datetime.fromtimestamp(
            NOW.timestamp() + 1,
            tz=timezone.utc,
        ),
    )

    assert len(first_alerts) == 1
    assert second_alerts == []


def test_detects_protected_server_destination_fanout():
    detector = ServerBehaviorDetector(
        fanout_unique_dst_threshold=2,
        fanout_connection_threshold=3,
    )
    packets = [
        tcp_packet(dst_ip="10.0.0.1", src_port=40001),
        tcp_packet(dst_ip="10.0.0.2", src_port=40002),
        tcp_packet(dst_ip="10.0.0.2", src_port=40003),
    ]

    alerts = detector.detect(packets, now=NOW)

    assert [alert["attack_type"] for alert in alerts] == [
        "SERVER_EGRESS",
        "SERVER_EGRESS",
        "LATERAL_MOVEMENT",
    ]
    fanout = alerts[-1]
    assert fanout["severity"] == "critical"
    assert fanout["response_level"] == "L3"
    assert fanout["recommended_action"] == "drop"
    assert fanout["evidence"]["unique_dst_ip_count"] == 2
    assert fanout["evidence"]["connection_count"] == 3
    assert fanout["evidence"]["destination_ips"] == [
        "10.0.0.1",
        "10.0.0.2",
    ]


def test_fanout_ignores_connections_outside_window():
    detector = ServerBehaviorDetector(
        fanout_window_sec=30,
        fanout_unique_dst_threshold=2,
        fanout_connection_threshold=2,
    )
    detector.detect(
        [
            tcp_packet(
                dst_ip="10.0.0.1",
                timestamp=NOW.timestamp() - 31,
            ),
        ],
        now=NOW,
    )

    alerts = detector.detect(
        [
            tcp_packet(
                dst_ip="10.0.0.2",
                src_port=40001,
                timestamp=NOW.timestamp(),
            ),
        ],
        now=NOW,
    )

    assert [alert["attack_type"] for alert in alerts] == ["SERVER_EGRESS"]


def test_detects_sustained_outbound_volume_on_server_initiated_flow():
    detector = ServerBehaviorDetector(
        volume_window_sec=1,
        outbound_bps_threshold=8_000,
        outbound_sustained_windows=1,
    )
    packets = [
        tcp_packet(packet_size=60),
        tcp_packet(flags="PA", packet_size=2_000),
    ]

    alerts = detector.detect(packets, now=NOW)

    assert [alert["attack_type"] for alert in alerts] == [
        "SERVER_EGRESS",
        "DATA_EXFILTRATION",
    ]
    exfiltration = alerts[-1]
    assert exfiltration["evidence"]["bit_count"] == 16_480
    assert exfiltration["evidence"]["bps"] == 16_480
    assert exfiltration["evidence"]["sustained_windows"] == 1


def test_volume_rule_ignores_large_normal_server_response():
    detector = ServerBehaviorDetector(
        volume_window_sec=1,
        outbound_bps_threshold=8_000,
        outbound_sustained_windows=1,
    )

    alerts = detector.detect(
        [
            tcp_packet(flags="SA", packet_size=60),
            tcp_packet(flags="PA", packet_size=2_000),
        ],
        now=NOW,
    )

    assert alerts == []


def test_volume_rule_requires_configured_sustained_windows():
    detector = ServerBehaviorDetector(
        volume_window_sec=10,
        outbound_bps_threshold=800,
        outbound_sustained_windows=2,
    )

    first_alerts = detector.detect(
        [
            tcp_packet(packet_size=60),
            tcp_packet(flags="PA", packet_size=2_000),
        ],
        now=NOW,
    )
    second_time = datetime.fromtimestamp(
        NOW.timestamp() + 1,
        tz=timezone.utc,
    )
    second_alerts = detector.detect(
        [
            tcp_packet(
                flags="PA",
                packet_size=2_000,
                timestamp=second_time.timestamp(),
            ),
        ],
        now=second_time,
    )

    assert [alert["attack_type"] for alert in first_alerts] == [
        "SERVER_EGRESS",
    ]
    assert [alert["attack_type"] for alert in second_alerts] == [
        "DATA_EXFILTRATION",
    ]


def test_volume_rule_uses_learned_baseline_multiplier():
    detector = ServerBehaviorDetector(
        volume_window_sec=1,
        outbound_bps_threshold=1_000,
        outbound_baseline_multiplier=3,
        outbound_baseline_min_samples=2,
        outbound_sustained_windows=1,
    )
    detector.detect([tcp_packet(packet_size=60)], now=NOW)

    second_time = datetime.fromtimestamp(
        NOW.timestamp() + 2,
        tz=timezone.utc,
    )
    detector.detect(
        [
            tcp_packet(
                flags="PA",
                packet_size=60,
                timestamp=second_time.timestamp(),
            ),
        ],
        now=second_time,
    )

    third_time = datetime.fromtimestamp(
        NOW.timestamp() + 4,
        tz=timezone.utc,
    )
    alerts = detector.detect(
        [
            tcp_packet(
                flags="PA",
                packet_size=400,
                timestamp=third_time.timestamp(),
            ),
        ],
        now=third_time,
    )

    assert [alert["attack_type"] for alert in alerts] == [
        "DATA_EXFILTRATION",
    ]
    evidence = alerts[0]["evidence"]
    assert evidence["baseline_bps"] == 480
    assert evidence["effective_bps_threshold"] == 1_440


def test_detects_periodic_server_beacon():
    detector = ServerBehaviorDetector(
        beacon_window_sec=300,
        beacon_min_connections=6,
        beacon_min_interval_sec=20,
        beacon_max_interval_sec=90,
        beacon_max_jitter_ratio=0.2,
    )
    packets = [
        tcp_packet(
            src_port=40000 + index,
            timestamp=NOW.timestamp() + (index * 30),
        )
        for index in range(6)
    ]
    detection_time = datetime.fromtimestamp(
        NOW.timestamp() + 150,
        tz=timezone.utc,
    )

    alerts = detector.detect(packets, now=detection_time)

    assert [alert["attack_type"] for alert in alerts] == [
        "SERVER_EGRESS",
        "C2_BEACON",
    ]
    beacon = alerts[-1]
    assert beacon["detection_rule"] == "periodic_server_egress"
    assert beacon["evidence"]["intervals_seconds"] == [
        30.0,
        30.0,
        30.0,
        30.0,
        30.0,
    ]
    assert beacon["evidence"]["median_interval_seconds"] == 30.0
    assert beacon["evidence"]["jitter_ratio"] == 0.0


def test_beacon_rule_ignores_irregular_connection_intervals():
    detector = ServerBehaviorDetector(
        beacon_window_sec=300,
        beacon_min_connections=6,
        beacon_min_interval_sec=20,
        beacon_max_interval_sec=90,
        beacon_max_jitter_ratio=0.2,
    )
    offsets = [0, 20, 80, 100, 200, 250]
    packets = [
        tcp_packet(
            src_port=40000 + index,
            timestamp=NOW.timestamp() + offset,
        )
        for index, offset in enumerate(offsets)
    ]
    detection_time = datetime.fromtimestamp(
        NOW.timestamp() + offsets[-1],
        tz=timezone.utc,
    )

    alerts = detector.detect(packets, now=detection_time)

    assert [alert["attack_type"] for alert in alerts] == ["SERVER_EGRESS"]


def test_server_behavior_alerts_use_common_security_event_contract():
    alert_types = [
        (
            "POST_COMPROMISE",
            "SERVER_EGRESS",
            "protected_server_tcp_egress",
        ),
        (
            "POST_COMPROMISE",
            "LATERAL_MOVEMENT",
            "protected_server_destination_fanout",
        ),
        (
            "EXFILTRATION",
            "DATA_EXFILTRATION",
            "server_initiated_outbound_bps",
        ),
        (
            "COMMAND_AND_CONTROL",
            "C2_BEACON",
            "periodic_server_egress",
        ),
    ]
    alerts = [
        {
            "attack_category": category,
            "attack_type": attack_type,
            "severity": "high",
            "confidence": "high",
            "src_ip": "10.0.0.100",
            "dst_ip": "10.0.0.3",
            "protocol": "TCP",
            "detection_rule": detection_rule,
            "recommended_action": "alert",
            "response_level": "L2",
            "evidence": {"matched_conditions": [detection_rule]},
        }
        for category, attack_type, detection_rule in alert_types
    ]
    builder = SecurityEventBuilder()

    payload = builder.build_security_events(
        {"window_sec": 1},
        [],
        server_behavior_alerts=alerts,
    )

    assert [event["attack_type"] for event in payload["events"]] == [
        item[1]
        for item in alert_types
    ]
    assert all(event["mitigation"] is None for event in payload["events"])
    assert all(event["status"] == "detected" for event in payload["events"])
