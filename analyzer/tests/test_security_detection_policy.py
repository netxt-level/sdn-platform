from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from analyzer.app.config import load_config
from analyzer.app.detection.flood import (
    FloodThresholds,
    IcmpFloodDetector,
    UdpFloodDetector,
)
from analyzer.app.detection.port_scan import PortScanDetector
from analyzer.app.detection.security_events import (
    PendingSecurityEventQueue,
    SecurityEventBuilder,
)
from analyzer.app.detection.syn_flood import SynFloodDetector


def tcp_syn_packets(
    src_ip="10.0.0.2",
    dst_ip="10.0.0.4",
    ports=range(1, 16),
):
    return [
        {
            "protocol": "TCP",
            "tcp_flags": "S",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 40000 + port,
            "dst_port": port,
        }
        for port in ports
    ]


def tcp_syn_same_service(
    count,
    src_ip="10.0.0.2",
    dst_ip="10.0.0.4",
    dst_port=80,
):
    return [
        {
            "protocol": "TCP",
            "tcp_flags": "S",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 40000 + index,
            "dst_port": dst_port,
        }
        for index in range(count)
    ]


def tcp_normal_handshakes(count):
    packets = []
    for index in range(count):
        client_port = 40000 + index
        packets.extend(
            [
                {
                    "protocol": "TCP",
                    "tcp_flags": "S",
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.4",
                    "src_port": client_port,
                    "dst_port": 80,
                },
                {
                    "protocol": "TCP",
                    "tcp_flags": "SA",
                    "src_ip": "10.0.0.4",
                    "dst_ip": "10.0.0.2",
                    "src_port": 80,
                    "dst_port": client_port,
                },
                {
                    "protocol": "TCP",
                    "tcp_flags": "A",
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.4",
                    "src_port": client_port,
                    "dst_port": 80,
                },
            ]
        )
    return packets


def icmp_packets(
    count,
    src_ip="10.0.0.2",
    dst_ip="10.0.0.4",
    icmp_type=8,
):
    return [
        {
            "protocol": "ICMP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "icmp_type": icmp_type,
            "icmp_code": 0,
            "packet_size": 100,
        }
        for _ in range(count)
    ]


def udp_packets(
    count,
    src_ip="10.0.0.2",
    dst_ip="10.0.0.4",
    dst_port=9999,
    packet_size=1000,
):
    return [
        {
            "protocol": "UDP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 50000 + index,
            "dst_port": dst_port,
            "packet_size": packet_size,
        }
        for index in range(count)
    ]


class PortScanDetectionPolicyTest(unittest.TestCase):
    def test_port_scan_below_unique_port_threshold_is_not_detected(self):
        detector = PortScanDetector(
            unique_port_threshold=15,
            syn_count_threshold=15,
        )

        alerts = detector.detect(tcp_syn_packets(ports=range(1, 15)))

        self.assertEqual(alerts, [])

    def test_vertical_port_scan_contains_korean_evidence(self):
        detector = PortScanDetector(
            unique_port_threshold=15,
            syn_count_threshold=30,
        )

        alert = detector.detect(tcp_syn_packets())[0]

        self.assertEqual(alert["attack_type"], "PORT_SCAN")
        self.assertEqual(alert["response_level"], "L1")
        self.assertEqual(alert["recommended_action"], "alert")
        self.assertEqual(alert["score"], 50)
        self.assertEqual(alert["evidence"]["scan_type"], "vertical")
        self.assertEqual(alert["evidence"]["syn_count"], 15)
        self.assertEqual(len(alert["evidence"]["unique_dst_ports"]), 15)
        self.assertIn(
            "단일 대상의 고유 목적지 포트 기준 초과",
            alert["matched_conditions"],
        )

    def test_horizontal_port_scan_works_with_small_topology(self):
        detector = PortScanDetector(
            horizontal_target_threshold=3,
            syn_count_threshold=3,
        )
        packets = []
        for index in range(3):
            packets.extend(
                tcp_syn_packets(
                    dst_ip=f"10.0.0.{index + 3}",
                    ports=[22],
                )
            )

        alert = detector.detect(packets)[0]

        self.assertEqual(alert["evidence"]["scan_type"], "horizontal")
        self.assertEqual(alert["evidence"]["window_seconds"], 30)
        self.assertEqual(alert["evidence"]["target_count"], 3)
        self.assertEqual(alert["evidence"]["target_ips"], [
            "10.0.0.3",
            "10.0.0.4",
            "10.0.0.5",
        ])

    def test_port_scan_cooldown_suppresses_repeated_alert(self):
        detector = PortScanDetector(
            unique_port_threshold=15,
            syn_count_threshold=15,
        )

        first = detector.detect(tcp_syn_packets())
        second = detector.detect(tcp_syn_packets())

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])

    def test_port_scan_handles_naive_datetime_timestamp(self):
        detector = PortScanDetector(
            unique_port_threshold=15,
            syn_count_threshold=30,
        )
        packets = tcp_syn_packets()
        for packet in packets:
            packet["timestamp"] = datetime.now(timezone.utc).replace(tzinfo=None)

        alert = detector.detect(packets)[0]

        self.assertEqual(alert["evidence"]["scan_type"], "vertical")

    def test_port_scan_ignores_invalid_ports(self):
        detector = PortScanDetector(
            unique_port_threshold=1,
            syn_count_threshold=1,
        )
        packets = [
            {
                "protocol": "TCP",
                "tcp_flags": "S",
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.4",
                "src_port": 40000,
                "dst_port": port,
            }
            for port in [-1, 0, 70000, "abc"]
        ]

        self.assertEqual(detector.detect(packets), [])


class FloodDetectionPolicyTest(unittest.TestCase):
    def test_normal_icmp_traffic_is_not_detected(self):
        detector = IcmpFloodDetector(
            FloodThresholds(
                pps=10,
                high_pps=20,
                critical_pps=50,
                minimum_packets=5,
            )
        )

        first = detector.detect(icmp_packets(3), window_sec=1)
        second = detector.detect(icmp_packets(3), window_sec=1)

        self.assertEqual(first, [])
        self.assertEqual(second, [])

    def test_icmp_flood_requires_repeated_exceeded_windows(self):
        detector = IcmpFloodDetector(
            FloodThresholds(
                pps=5,
                high_pps=20,
                critical_pps=50,
                minimum_packets=5,
            )
        )

        first = detector.detect(icmp_packets(5), window_sec=1)
        second = detector.detect(icmp_packets(5), window_sec=1)

        self.assertEqual(first, [])
        self.assertEqual(second[0]["attack_type"], "ICMP_FLOOD")
        self.assertEqual(second[0]["evidence"]["icmp_type"], 8)
        self.assertEqual(second[0]["response_level"], "L1")
        self.assertEqual(second[0]["recommended_action"], "alert")
        self.assertIn("여러 분석 구간에서 반복 초과", second[0]["matched_conditions"])

    def test_icmp_flood_ignores_non_echo_request_messages(self):
        detector = IcmpFloodDetector(
            FloodThresholds(
                pps=1,
                high_pps=5,
                critical_pps=10,
                minimum_packets=1,
                required_exceeded_windows=1,
            )
        )
        packets = icmp_packets(10, icmp_type=0) + icmp_packets(10, icmp_type=3)

        self.assertEqual(detector.detect(packets, window_sec=1), [])

    def test_icmp_flood_history_resets_after_empty_window(self):
        detector = IcmpFloodDetector(
            FloodThresholds(
                pps=5,
                high_pps=20,
                critical_pps=50,
                minimum_packets=5,
            )
        )

        detector.detect(icmp_packets(5), window_sec=1)
        detector.detect([], window_sec=1)
        after_gap = detector.detect(icmp_packets(5), window_sec=1)

        self.assertEqual(after_gap, [])

    def test_flood_state_is_cleaned_after_retention_window(self):
        detector = IcmpFloodDetector(
            FloodThresholds(
                pps=5,
                high_pps=20,
                critical_pps=50,
                minimum_packets=5,
                retention_windows=1,
            )
        )

        detector.detect(icmp_packets(5), window_sec=1)
        detector.detect([], window_sec=1)
        detector.detect([], window_sec=1)

        self.assertEqual(detector.history, {})
        self.assertEqual(detector.last_seen_window, {})

    def test_udp_critical_first_limits_then_repeated_critical_drops(self):
        detector = UdpFloodDetector(
            FloodThresholds(
                pps=100,
                high_pps=200,
                critical_pps=500,
                minimum_packets=2,
                bps=1000,
                high_bps=5000,
                critical_bps=10000,
            )
        )

        first = detector.detect(udp_packets(2), window_sec=1)[0]
        second = detector.detect(udp_packets(2), window_sec=1)[0]

        self.assertEqual(first["response_level"], "L2")
        self.assertEqual(first["recommended_action"], "rate_limit")
        self.assertEqual(first["evidence"]["destination_port"], 9999)
        self.assertEqual(first["evidence"]["dominant_dst_port"], 9999)
        self.assertEqual(first["evidence"]["dominant_port_ratio"], 1.0)
        self.assertEqual(second["response_level"], "L3")
        self.assertEqual(second["recommended_action"], "drop")

    def test_invalid_packet_size_and_zero_window_are_handled(self):
        detector = UdpFloodDetector(
            FloodThresholds(
                pps=1,
                high_pps=5,
                critical_pps=10,
                minimum_packets=1,
                bps=1,
                high_bps=5,
                critical_bps=10,
                required_exceeded_windows=1,
            )
        )
        packets = udp_packets(1, packet_size=-100)

        alert = detector.detect(packets, window_sec=0)[0]

        self.assertEqual(alert["evidence"]["bps"], 0)
        self.assertEqual(alert["evidence"]["pps"], 1)
        self.assertEqual(alert["evidence"]["window_seconds"], 1.0)

    def test_udp_flood_is_grouped_by_destination_port(self):
        detector = UdpFloodDetector(
            FloodThresholds(
                pps=3,
                high_pps=10,
                critical_pps=20,
                minimum_packets=3,
                required_exceeded_windows=1,
            )
        )
        mixed_ports = udp_packets(2, dst_port=9999) + udp_packets(2, dst_port=8888)
        focused_port = udp_packets(3, dst_port=9999)

        self.assertEqual(detector.detect(mixed_ports, window_sec=1), [])
        alert = detector.detect(focused_port, window_sec=1)[0]

        self.assertEqual(alert["evidence"]["destination_port"], 9999)
        self.assertEqual(alert["evidence"]["unique_dst_port_count"], 1)


class SynFloodDetectionPolicyTest(unittest.TestCase):
    def test_syn_flood_focuses_on_single_service(self):
        detector = SynFloodDetector(
            pps_threshold=3,
            high_pps_threshold=10,
            critical_pps_threshold=20,
            minimum_syn_count=3,
        )

        first = detector.detect(tcp_syn_same_service(4), window_sec=1)
        second = detector.detect(tcp_syn_same_service(4), window_sec=1)

        self.assertEqual(first, [])
        self.assertEqual(second[0]["attack_type"], "SYN_FLOOD")
        self.assertEqual(second[0]["response_level"], "L2")
        self.assertEqual(second[0]["recommended_action"], "rate_limit")
        self.assertEqual(second[0]["evidence"]["destination_port"], 80)

    def test_normal_tcp_handshake_is_not_syn_flood(self):
        detector = SynFloodDetector(
            pps_threshold=3,
            high_pps_threshold=10,
            critical_pps_threshold=20,
            minimum_syn_count=3,
        )

        first = detector.detect(tcp_normal_handshakes(4), window_sec=1)
        second = detector.detect(tcp_normal_handshakes(4), window_sec=1)

        self.assertEqual(first, [])
        self.assertEqual(second, [])

    def test_syn_flood_response_count_is_order_independent(self):
        detector = SynFloodDetector(
            pps_threshold=3,
            high_pps_threshold=10,
            critical_pps_threshold=20,
            minimum_syn_count=3,
        )
        packets = tcp_normal_handshakes(4)
        reversed_packets = list(reversed(packets))

        first = detector.detect(reversed_packets, window_sec=1)
        second = detector.detect(reversed_packets, window_sec=1)

        self.assertEqual(first, [])
        self.assertEqual(second, [])

    def test_syn_flood_counts_only_syn_ack_as_response(self):
        detector = SynFloodDetector(
            pps_threshold=3,
            high_pps_threshold=10,
            critical_pps_threshold=20,
            minimum_syn_count=3,
            required_exceeded_windows=1,
        )
        packets = tcp_syn_same_service(4)
        packets.extend(
            [
                {
                    "protocol": "TCP",
                    "tcp_flags": "SA",
                    "src_ip": "10.0.0.4",
                    "dst_ip": "10.0.0.2",
                    "src_port": 80,
                    "dst_port": 40000,
                },
                {
                    "protocol": "TCP",
                    "tcp_flags": "A",
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.4",
                    "src_port": 40000,
                    "dst_port": 80,
                },
            ]
        )

        alert = detector.detect(packets, window_sec=1)[0]

        self.assertEqual(alert["evidence"]["response_count"], 1)
        self.assertEqual(alert["evidence"]["syn_response_ratio"], 4)

    def test_syn_flood_does_not_replace_port_scan(self):
        detector = SynFloodDetector(
            pps_threshold=3,
            high_pps_threshold=10,
            critical_pps_threshold=20,
            max_unique_ports=2,
            minimum_syn_count=3,
        )

        packets = tcp_syn_packets(ports=range(1, 6))

        self.assertEqual(detector.detect(packets, window_sec=1), [])


class SecurityEventBuilderTest(unittest.TestCase):
    def test_detection_is_converted_to_security_event(self):
        builder = SecurityEventBuilder()
        detector = UdpFloodDetector(
            FloodThresholds(
                pps=100,
                high_pps=200,
                critical_pps=500,
                minimum_packets=2,
                bps=1000,
                high_bps=5000,
                critical_bps=10000,
            )
        )
        detector.detect(udp_packets(2), window_sec=1)
        alert = detector.detect(udp_packets(2), window_sec=1)[0]

        event = builder.build_security_events(
            {"window_sec": 1},
            [alert],
        )["events"][0]

        self.assertEqual(event["attack_type"], "UDP_FLOOD")
        self.assertEqual(event["mitigation"]["action"], "DROP")
        self.assertEqual(event["mitigation"]["match"]["ip_proto"], 17)
        self.assertEqual(event["mitigation"]["match"]["udp_dst"], 9999)
        self.assertEqual(event["evidence"]["score"], 90)
        self.assertTrue(event["event_id"].startswith("evt-"))
        self.assertEqual(len(event["event_fingerprint"]), 64)

    def test_icmp_flood_mitigation_contains_icmp_type(self):
        builder = SecurityEventBuilder()
        detector = IcmpFloodDetector(
            FloodThresholds(
                pps=1,
                high_pps=2,
                critical_pps=100,
                minimum_packets=2,
                required_exceeded_windows=1,
            )
        )
        alert = detector.detect(icmp_packets(2), window_sec=1)[0]

        event = builder.build_security_events(
            {"window_sec": 1},
            [alert],
        )["events"][0]

        self.assertEqual(event["mitigation"]["action"], "RATE_LIMIT")
        self.assertEqual(event["mitigation"]["match"]["ip_proto"], 1)
        self.assertEqual(event["mitigation"]["match"]["icmpv4_type"], 8)

    def test_syn_flood_mitigation_contains_tcp_destination_port(self):
        builder = SecurityEventBuilder()
        detector = SynFloodDetector(
            pps_threshold=3,
            high_pps_threshold=10,
            critical_pps_threshold=20,
            minimum_syn_count=3,
        )
        detector.detect(tcp_syn_same_service(4), window_sec=1)
        alert = detector.detect(tcp_syn_same_service(4), window_sec=1)[0]

        event = builder.build_security_events(
            {"window_sec": 1},
            [alert],
        )["events"][0]

        self.assertEqual(event["mitigation"]["action"], "RATE_LIMIT")
        self.assertEqual(event["mitigation"]["match"]["ip_proto"], 6)
        self.assertEqual(event["mitigation"]["match"]["tcp_dst"], 80)

    def test_horizontal_port_scan_mitigation_keeps_destination_port(self):
        builder = SecurityEventBuilder()
        detector = PortScanDetector(
            horizontal_target_threshold=3,
            syn_count_threshold=3,
        )
        packets = []
        for index in range(6):
            packets.extend(
                tcp_syn_packets(
                    dst_ip=f"10.0.0.{index + 3}",
                    ports=[22],
                )
            )
        alert = detector.detect(packets)[0]

        event = builder.build_security_events(
            {"window_sec": 1},
            [alert],
        )["events"][0]

        self.assertEqual(event["mitigation"]["action"], "RATE_LIMIT")
        self.assertEqual(event["mitigation"]["match"]["tcp_dst"], 22)
        self.assertNotIn("ipv4_dst", event["mitigation"]["match"])

    def test_duplicate_event_is_suppressed_inside_dedup_window(self):
        builder = SecurityEventBuilder()
        detector = PortScanDetector(
            unique_port_threshold=15,
            syn_count_threshold=15,
        )
        alert = detector.detect(tcp_syn_packets())[0]

        first = builder.build_security_events({"window_sec": 1}, [alert])
        second = builder.build_security_events({"window_sec": 1}, [alert])

        self.assertEqual(len(first["events"]), 1)
        self.assertEqual(second["events"], [])

    def test_escalated_event_bypasses_dedup_window(self):
        builder = SecurityEventBuilder()
        medium_detection = {
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.4",
            "protocol": "ICMP",
            "attack_category": "FLOOD",
            "attack_type": "ICMP_FLOOD",
            "severity": "medium",
            "confidence": "medium",
            "detection_rule": "icmp_flood_rate_threshold",
            "recommended_action": "alert",
            "response_level": "L1",
            "matched_conditions": ["PPS 기준 초과"],
            "score": 60,
        }
        high_detection = {
            **medium_detection,
            "severity": "high",
            "recommended_action": "rate_limit",
            "response_level": "L2",
            "score": 80,
        }

        first = builder.build_security_events({"window_sec": 1}, [medium_detection])
        second = builder.build_security_events({"window_sec": 1}, [high_detection])

        self.assertEqual(len(first["events"]), 1)
        self.assertEqual(len(second["events"]), 1)
        self.assertEqual(second["events"][0]["response_level"], "L2")

    def test_unsent_event_can_be_rebuilt_after_forget(self):
        builder = SecurityEventBuilder()
        detector = PortScanDetector(
            unique_port_threshold=15,
            syn_count_threshold=30,
        )
        alert = detector.detect(tcp_syn_packets())[0]

        first = builder.build_security_events({"window_sec": 1}, [alert])
        duplicate = builder.build_security_events({"window_sec": 1}, [alert])
        builder.forget_events(first["events"])
        retried = builder.build_security_events({"window_sec": 1}, [alert])

        self.assertEqual(len(first["events"]), 1)
        self.assertEqual(duplicate["events"], [])
        self.assertEqual(len(retried["events"]), 1)

    def test_pending_event_queue_keeps_failed_events_for_retry(self):
        queue = PendingSecurityEventQueue(max_size=2)
        first = {"event_id": "evt-1", "attack_type": "PORT_SCAN"}
        second = {"event_id": "evt-2", "attack_type": "ICMP_FLOOD"}
        third = {"event_id": "evt-3", "attack_type": "UDP_FLOOD"}

        self.assertEqual(queue.add([first, first]), [])
        self.assertEqual(len(queue), 1)

        dropped = queue.add([second, third])

        self.assertEqual(dropped, [first])
        self.assertEqual(len(queue), 2)
        self.assertEqual(
            queue.payload(timestamp="2026-07-10T00:00:00+00:00", analyzer_id="a1"),
            {
                "timestamp": "2026-07-10T00:00:00+00:00",
                "analyzer_id": "a1",
                "events": [second, third],
            },
        )

        queue.clear()
        self.assertEqual(len(queue), 0)


class ConfigValidationTest(unittest.TestCase):
    def test_default_interface_matches_docker_environment(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(load_config().interface, "eth0")

    def test_zero_window_is_rejected(self):
        with patch.dict("os.environ", {"ANALYZER_WINDOW_SEC": "0"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "ANALYZER_WINDOW_SEC"):
                load_config()

    def test_invalid_threshold_order_is_rejected(self):
        env = {
            "ICMP_PPS_THRESHOLD": "100",
            "ICMP_HIGH_PPS_THRESHOLD": "50",
            "ICMP_CRITICAL_PPS_THRESHOLD": "200",
        }
        with patch.dict("os.environ", env, clear=True):
            with self.assertRaisesRegex(RuntimeError, "ICMP_PPS_THRESHOLD"):
                load_config()


if __name__ == "__main__":
    unittest.main()
