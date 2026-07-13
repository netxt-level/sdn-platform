from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from analyzer.app.config import load_config
from analyzer.app.detection.correlation import correlate_detections
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
from analyzer.app.packet.parser import parse_packet
from analyzer.app.packet.summary import PacketSummaryBuilder
from scapy.layers.l2 import ARP, Ether


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


def packets_at(packets, timestamp):
    for packet in packets:
        packet["timestamp"] = timestamp
    return packets


class PacketSummaryPolicyTest(unittest.TestCase):
    def test_packet_summary_uses_actual_window_seconds(self):
        builder = PacketSummaryBuilder()

        summary = builder.build_packet_summary(
            icmp_packets(10),
            window_sec=2.5,
        )

        self.assertEqual(summary["window_sec"], 2.5)

    def test_packet_summary_groups_ephemeral_source_ports(self):
        builder = PacketSummaryBuilder(max_host_stats=50)
        packets = tcp_syn_same_service(100)

        summary = builder.build_packet_summary(packets)

        self.assertEqual(len(summary["host_stats"]), 1)
        self.assertEqual(summary["host_stats"][0]["packet_count"], 100)
        self.assertIsNone(summary["host_stats"][0]["src_port"])
        self.assertIsNone(summary["host_stats"][0]["dst_port"])

    def test_packet_summary_groups_destination_ports_for_host_traffic(self):
        builder = PacketSummaryBuilder(max_host_stats=50)
        packets = (
            tcp_syn_same_service(5, dst_port=80)
            + tcp_syn_same_service(7, dst_port=443)
        )

        summary = builder.build_packet_summary(packets)

        self.assertEqual(len(summary["host_stats"]), 1)
        self.assertEqual(summary["host_stats"][0]["packet_count"], 12)

    def test_packet_summary_limits_host_stats_to_top_flows(self):
        builder = PacketSummaryBuilder(max_host_stats=3)
        packets = []
        for index in range(5):
            packets.extend(
                udp_packets(
                    index + 1,
                    dst_ip=f"10.0.0.{index + 3}",
                    dst_port=9000 + index,
                    packet_size=100,
                )
            )

        summary = builder.build_packet_summary(packets)

        self.assertEqual(len(summary["host_stats"]), 3)
        self.assertEqual(
            [item["packet_count"] for item in summary["host_stats"]],
            [5, 4, 3],
        )

    def test_packet_summary_normalizes_unknown_protocol_to_other(self):
        builder = PacketSummaryBuilder(max_host_stats=50)
        summary = builder.build_packet_summary([
            {
                "protocol": "UNKNOWN",
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.4",
                "packet_size": 100,
            }
        ])

        self.assertEqual(summary["protocol_stats"], {"OTHER": 1})
        self.assertEqual(summary["host_stats"][0]["protocol"], "OTHER")

    def test_parser_marks_arp_packets_as_arp(self):
        packet = Ether() / ARP(
            psrc="10.0.0.2",
            pdst="10.0.0.4",
            hwsrc="00:00:00:00:00:02",
            hwdst="00:00:00:00:00:04",
        )

        metadata = parse_packet(packet)

        self.assertEqual(metadata["protocol"], "ARP")
        self.assertEqual(metadata["src_ip"], "10.0.0.2")
        self.assertEqual(metadata["dst_ip"], "10.0.0.4")


class DetectionCorrelationPolicyTest(unittest.TestCase):
    def test_port_scan_and_multi_service_syn_flood_are_correlated(self):
        port_scan = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "attack_type": "PORT_SCAN",
            "detection_rule": "tcp_syn_port_scan",
            "severity": "high",
            "response_level": "L2",
            "recommended_action": "rate_limit",
            "score": 80,
            "evidence": {
                "scan_type": "vertical",
                "unique_dst_port_count": 50,
            },
        }
        syn_flood = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "attack_type": "SYN_FLOOD",
            "detection_rule": "tcp_syn_multi_service_rate",
            "severity": "critical",
            "response_level": "L3",
            "recommended_action": "drop",
            "score": 90,
            "matched_conditions": ["TCP SYN 패킷"],
            "evidence": {
                "scan_like": True,
                "unique_dst_port_count": 50,
            },
        }

        correlated = correlate_detections([port_scan, syn_flood])

        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0]["attack_type"], "SYN_FLOOD")
        self.assertEqual(
            correlated[0]["evidence"]["correlation_policy"],
            "multi_service_syn_flood_over_port_scan",
        )
        self.assertEqual(correlated[0]["evidence"]["suppressed_detection_count"], 1)
        self.assertEqual(
            correlated[0]["evidence"]["related_detections"][0]["attack_type"],
            "PORT_SCAN",
        )

    def test_higher_response_detection_is_not_suppressed(self):
        port_scan = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "attack_type": "PORT_SCAN",
            "detection_rule": "tcp_syn_port_scan",
            "response_level": "L3",
            "evidence": {},
        }
        syn_flood = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "attack_type": "SYN_FLOOD",
            "detection_rule": "tcp_syn_multi_service_rate",
            "response_level": "L2",
            "evidence": {"scan_like": True},
        }

        correlated = correlate_detections([port_scan, syn_flood])

        self.assertEqual(len(correlated), 2)

    def test_udp_pair_flood_suppresses_weaker_service_alerts(self):
        service_dns = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "UDP",
            "attack_type": "UDP_FLOOD",
            "detection_rule": "udp_flood_rate_threshold",
            "response_level": "L3",
            "recommended_action": "drop",
            "score": 90,
            "evidence": {
                "aggregation_scope": "service",
                "destination_port": 53,
                "pps": 1600,
                "bps": 1000000,
                "packet_count": 1600,
            },
        }
        service_ntp = {
            **service_dns,
            "evidence": {
                **service_dns["evidence"],
                "destination_port": 123,
            },
        }
        pair_total = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "UDP",
            "attack_type": "UDP_FLOOD",
            "detection_rule": "udp_flood_rate_threshold_pair_total",
            "response_level": "L3",
            "recommended_action": "drop",
            "score": 90,
            "matched_conditions": ["여러 목적지 포트 합산 기준 초과"],
            "evidence": {
                "aggregation_scope": "pair",
                "unique_dst_port_count": 2,
                "sample_dst_ports": [53, 123],
            },
        }

        correlated = correlate_detections([service_dns, service_ntp, pair_total])

        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0]["detection_rule"], "udp_flood_rate_threshold_pair_total")
        self.assertEqual(
            correlated[0]["evidence"]["correlation_policy"],
            "udp_pair_total_over_service_ports",
        )
        self.assertEqual(
            [item["destination_port"] for item in correlated[0]["evidence"]["related_service_detections"]],
            [53, 123],
        )


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

    def test_horizontal_port_scan_requires_minimum_syn_attempts(self):
        detector = PortScanDetector(
            horizontal_target_threshold=3,
            syn_count_threshold=30,
        )
        packets = []
        for index in range(3):
            packets.extend(
                tcp_syn_packets(
                    dst_ip=f"10.0.0.{index + 3}",
                    ports=[22],
                )
            )

        self.assertEqual(detector.detect(packets), [])

    def test_port_scan_cooldown_suppresses_repeated_alert(self):
        detector = PortScanDetector(
            unique_port_threshold=15,
            syn_count_threshold=15,
        )

        first = detector.detect(tcp_syn_packets())
        second = detector.detect(tcp_syn_packets())

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])

    def test_port_scan_cooldown_allows_severity_escalation(self):
        detector = PortScanDetector(
            unique_port_threshold=15,
            syn_count_threshold=15,
            high_unique_dst_port_threshold=50,
        )

        first = detector.detect(tcp_syn_packets(ports=range(1, 16)))
        escalated = detector.detect(tcp_syn_packets(ports=range(1, 51)))

        self.assertEqual(len(first), 1)
        self.assertEqual(len(escalated), 1)
        self.assertGreater(escalated[0]["score"], first[0]["score"])
        self.assertEqual(escalated[0]["severity"], "high")

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

    def test_delayed_vertical_scan_uses_event_time(self):
        detector = PortScanDetector(
            window_sec=5,
            unique_port_threshold=15,
            syn_count_threshold=15,
        )
        delayed_timestamp = datetime.now(timezone.utc) - timedelta(seconds=20)
        packets = packets_at(tcp_syn_packets(), delayed_timestamp)

        alerts = detector.detect(packets)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"]["scan_type"], "vertical")
        self.assertEqual(alerts[0]["evidence"]["syn_count"], 15)

    def test_old_vertical_scan_is_not_replayed_from_event_time_bucket(self):
        detector = PortScanDetector(
            window_sec=5,
            unique_port_threshold=15,
            syn_count_threshold=15,
        )
        delayed_timestamp = datetime.now(timezone.utc) - timedelta(seconds=20)

        first = detector.detect(packets_at(tcp_syn_packets(), delayed_timestamp))
        second = detector.detect([])

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])

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

    def test_port_scan_ignores_invalid_ip_addresses(self):
        detector = PortScanDetector(
            unique_port_threshold=1,
            syn_count_threshold=1,
        )
        packets = tcp_syn_packets(src_ip="abc", dst_ip="999.999.999.999", ports=[80])

        self.assertEqual(detector.detect(packets), [])

    def test_trusted_source_uses_repeated_syns_in_small_topology(self):
        detector = PortScanDetector(
            horizontal_target_threshold=3,
            trusted_source_ips={"10.0.0.3"},
            trusted_horizontal_target_threshold=10,
            syn_count_threshold=30,
        )
        packets = []
        for index in range(3):
            packets.extend(
                tcp_syn_packets(
                    src_ip="10.0.0.3",
                    dst_ip=f"10.0.0.{index + 4}",
                    ports=[22],
                )
            )

        self.assertEqual(detector.detect(packets), [])

        repeated_detector = PortScanDetector(
            horizontal_target_threshold=3,
            trusted_source_ips={"10.0.0.3"},
            trusted_horizontal_target_threshold=10,
            syn_count_threshold=30,
        )
        repeated_packets = []
        for repeat in range(10):
            for index in range(3):
                repeated_packets.extend(
                    tcp_syn_packets(
                        src_ip="10.0.0.3",
                        dst_ip=f"10.0.0.{index + 4}",
                        ports=[22],
                    )
                )
        alert = repeated_detector.detect(repeated_packets)[0]

        self.assertEqual(alert["evidence"]["scan_type"], "horizontal")
        self.assertEqual(alert["evidence"]["target_count"], 3)
        self.assertEqual(alert["evidence"]["syn_count"], 30)
        self.assertIn("관리 호스트 기준 적용", alert["matched_conditions"])
        self.assertIn("관리 호스트 반복 SYN 기준 충족", alert["matched_conditions"])

    def test_port_scan_expires_old_buckets(self):
        detector = PortScanDetector(
            unique_port_threshold=15,
            syn_count_threshold=15,
        )
        old_timestamp = datetime.now(timezone.utc) - timedelta(seconds=90)
        old_packets = tcp_syn_packets(ports=range(1000, 1015))
        for packet in old_packets:
            packet["timestamp"] = old_timestamp

        current_packets = tcp_syn_packets()
        alerts = detector.detect(old_packets + current_packets)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"]["syn_count"], 15)
        self.assertLessEqual(len(detector.buckets), 2)


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

    def test_one_second_flood_survives_delayed_analysis(self):
        detector = IcmpFloodDetector(
            FloodThresholds(
                pps=5,
                high_pps=20,
                critical_pps=50,
                minimum_packets=5,
                required_exceeded_windows=1,
            )
        )
        timestamp = datetime.now(timezone.utc)
        packets = icmp_packets(6)
        for packet in packets:
            packet["timestamp"] = timestamp

        alerts = detector.detect(packets, window_sec=10)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"]["window_seconds"], 1.0)
        self.assertEqual(alerts[0]["evidence"]["analysis_window_seconds"], 10.0)
        self.assertEqual(alerts[0]["evidence"]["packet_count"], 6)

    def test_delayed_snapshot_processes_all_flood_buckets(self):
        detector = IcmpFloodDetector(
            FloodThresholds(
                pps=5,
                high_pps=20,
                critical_pps=50,
                minimum_packets=5,
            )
        )
        first_second = datetime.now(timezone.utc)
        second_second = first_second + timedelta(seconds=1)
        packets = icmp_packets(5) + icmp_packets(5)
        for packet in packets[:5]:
            packet["timestamp"] = first_second
        for packet in packets[5:]:
            packet["timestamp"] = second_second

        alerts = detector.detect(packets, window_sec=10)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"]["exceeded_windows"], 2)
        self.assertEqual(alerts[0]["recommended_action"], "alert")

    def test_non_adjacent_icmp_buckets_do_not_form_sustained_attack(self):
        detector = IcmpFloodDetector(
            FloodThresholds(
                pps=5,
                high_pps=20,
                critical_pps=50,
                minimum_packets=5,
            )
        )
        first_second = datetime.now(timezone.utc)
        later_second = first_second + timedelta(seconds=10)
        packets = icmp_packets(5) + icmp_packets(5)
        for packet in packets[:5]:
            packet["timestamp"] = first_second
        for packet in packets[5:]:
            packet["timestamp"] = later_second

        self.assertEqual(detector.detect(packets, window_sec=10), [])

    def test_same_icmp_bucket_split_across_calls_is_counted_once(self):
        detector = IcmpFloodDetector(
            FloodThresholds(
                pps=5,
                high_pps=20,
                critical_pps=50,
                minimum_packets=5,
            )
        )
        timestamp = datetime.now(timezone.utc)

        first = detector.detect(packets_at(icmp_packets(5), timestamp), window_sec=10)
        second = detector.detect(packets_at(icmp_packets(5), timestamp), window_sec=10)
        third = detector.detect(
            packets_at(icmp_packets(5), timestamp + timedelta(seconds=1)),
            window_sec=10,
        )

        self.assertEqual(first, [])
        self.assertEqual(second, [])
        self.assertEqual(third[0]["evidence"]["exceeded_windows"], 2)

    def test_split_icmp_bucket_packets_are_aggregated_before_threshold_check(self):
        detector = IcmpFloodDetector(
            FloodThresholds(
                pps=6,
                high_pps=20,
                critical_pps=50,
                minimum_packets=6,
                required_exceeded_windows=1,
            )
        )
        timestamp = datetime.now(timezone.utc)

        first = detector.detect(packets_at(icmp_packets(3), timestamp), window_sec=10)
        second = detector.detect(packets_at(icmp_packets(3), timestamp), window_sec=10)

        self.assertEqual(first, [])
        self.assertEqual(second[0]["evidence"]["packet_count"], 6)
        self.assertEqual(second[0]["evidence"]["exceeded_windows"], 1)

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

    def test_udp_flood_detects_distributed_destination_ports(self):
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

        aggregate_alert = detector.detect(mixed_ports, window_sec=1)[0]
        focused_alert = detector.detect(focused_port, window_sec=1)[0]

        self.assertNotIn("destination_port", aggregate_alert["evidence"])
        self.assertEqual(aggregate_alert["evidence"]["aggregation_scope"], "pair")
        self.assertEqual(aggregate_alert["evidence"]["unique_dst_port_count"], 2)
        self.assertEqual(focused_alert["evidence"]["destination_port"], 9999)
        self.assertEqual(focused_alert["evidence"]["aggregation_scope"], "service")

    def test_udp_service_alert_does_not_suppress_pair_total_alert(self):
        detector = UdpFloodDetector(
            FloodThresholds(
                pps=5,
                high_pps=10,
                critical_pps=20,
                minimum_packets=5,
                required_exceeded_windows=1,
            )
        )
        packets = udp_packets(6, dst_port=9999) + udp_packets(4, dst_port=8888)

        alerts = detector.detect(packets, window_sec=1)
        scopes = {alert["evidence"]["aggregation_scope"] for alert in alerts}
        pair_alert = next(
            alert for alert in alerts if alert["evidence"]["aggregation_scope"] == "pair"
        )

        self.assertEqual(scopes, {"service", "pair"})
        self.assertNotIn("destination_port", pair_alert["evidence"])
        self.assertEqual(pair_alert["evidence"]["unique_dst_port_count"], 2)

    def test_non_adjacent_udp_buckets_do_not_form_sustained_attack(self):
        detector = UdpFloodDetector(
            FloodThresholds(
                pps=3,
                high_pps=10,
                critical_pps=20,
                minimum_packets=3,
            )
        )
        first_second = datetime.now(timezone.utc)
        later_second = first_second + timedelta(seconds=10)
        packets = udp_packets(3) + udp_packets(3)
        for packet in packets[:3]:
            packet["timestamp"] = first_second
        for packet in packets[3:]:
            packet["timestamp"] = later_second

        self.assertEqual(detector.detect(packets, window_sec=10), [])

    def test_same_udp_bucket_split_across_calls_is_counted_once(self):
        detector = UdpFloodDetector(
            FloodThresholds(
                pps=3,
                high_pps=10,
                critical_pps=20,
                minimum_packets=3,
            )
        )
        timestamp = datetime.now(timezone.utc)

        first = detector.detect(packets_at(udp_packets(3), timestamp), window_sec=10)
        second = detector.detect(packets_at(udp_packets(3), timestamp), window_sec=10)
        third = detector.detect(
            packets_at(udp_packets(3), timestamp + timedelta(seconds=1)),
            window_sec=10,
        )

        self.assertEqual(first, [])
        self.assertEqual(second, [])
        self.assertEqual(third[0]["evidence"]["exceeded_windows"], 2)

    def test_split_udp_pair_bucket_is_aggregated_across_ports(self):
        detector = UdpFloodDetector(
            FloodThresholds(
                pps=4,
                high_pps=10,
                critical_pps=20,
                minimum_packets=4,
                required_exceeded_windows=1,
            )
        )
        timestamp = datetime.now(timezone.utc)

        first = detector.detect(
            packets_at(udp_packets(2, dst_port=9999), timestamp),
            window_sec=10,
        )
        second = detector.detect(
            packets_at(udp_packets(2, dst_port=8888), timestamp),
            window_sec=10,
        )

        self.assertEqual(first, [])
        self.assertEqual(second[0]["evidence"]["aggregation_scope"], "pair")
        self.assertEqual(second[0]["evidence"]["packet_count"], 4)
        self.assertEqual(second[0]["evidence"]["unique_dst_port_count"], 2)


class SynFloodDetectionPolicyTest(unittest.TestCase):
    def test_multi_service_syn_flood_is_not_missed_between_scan_thresholds(self):
        detector = SynFloodDetector(
            pps_threshold=100,
            high_pps_threshold=400,
            critical_pps_threshold=800,
            max_unique_ports=5,
            minimum_syn_count=30,
            required_exceeded_windows=1,
        )
        packets = []
        for dst_port in range(1, 7):
            packets.extend(
                tcp_syn_same_service(
                    150,
                    dst_port=dst_port,
                )
            )

        alerts = detector.detect(packets, window_sec=1)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["attack_type"], "SYN_FLOOD")
        self.assertEqual(alerts[0]["detection_rule"], "tcp_syn_multi_service_rate")
        self.assertEqual(alerts[0]["evidence"]["unique_dst_port_count"], 6)
        self.assertEqual(alerts[0]["evidence"]["syn_count"], 900)
        self.assertTrue(alerts[0]["evidence"]["scan_like"])

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

    def test_synack_without_final_ack_is_still_half_open(self):
        detector = SynFloodDetector(
            pps_threshold=120,
            high_pps_threshold=400,
            critical_pps_threshold=800,
            minimum_syn_count=30,
            required_exceeded_windows=1,
        )
        packets = tcp_syn_same_service(1000)
        for index in range(1000):
            packets.append({
                "protocol": "TCP",
                "tcp_flags": "SA",
                "src_ip": "10.0.0.4",
                "dst_ip": "10.0.0.2",
                "src_port": 80,
                "dst_port": 40000 + index,
            })

        alert = detector.detect(packets, window_sec=1)[0]

        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["evidence"]["response_count"], 1000)
        self.assertEqual(alert["evidence"]["completed_count"], 0)
        self.assertTrue(alert["evidence"]["completion_shortage"])
        self.assertIn("최종 ACK 완료율 부족", alert["matched_conditions"])

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

    def test_syn_flood_uses_packet_timestamp_buckets(self):
        detector = SynFloodDetector(
            pps_threshold=3,
            high_pps_threshold=10,
            critical_pps_threshold=20,
            minimum_syn_count=3,
        )
        first_second = datetime.now(timezone.utc)
        second_second = first_second + timedelta(seconds=1)
        packets = tcp_syn_same_service(4) + tcp_syn_same_service(4)
        for packet in packets[:4]:
            packet["timestamp"] = first_second
        for packet in packets[4:]:
            packet["timestamp"] = second_second

        alerts = detector.detect(packets, window_sec=10)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["attack_type"], "SYN_FLOOD")
        self.assertEqual(alerts[0]["evidence"]["window_seconds"], 1.0)
        self.assertEqual(alerts[0]["evidence"]["analysis_window_seconds"], 10.0)
        self.assertEqual(alerts[0]["evidence"]["exceeded_windows"], 2)

    def test_non_adjacent_syn_buckets_do_not_form_sustained_attack(self):
        detector = SynFloodDetector(
            pps_threshold=3,
            high_pps_threshold=10,
            critical_pps_threshold=20,
            minimum_syn_count=3,
        )
        first_second = datetime.now(timezone.utc)
        later_second = first_second + timedelta(seconds=10)
        packets = tcp_syn_same_service(4) + tcp_syn_same_service(4)
        for packet in packets[:4]:
            packet["timestamp"] = first_second
        for packet in packets[4:]:
            packet["timestamp"] = later_second

        self.assertEqual(detector.detect(packets, window_sec=10), [])

    def test_same_syn_bucket_split_across_calls_is_counted_once(self):
        detector = SynFloodDetector(
            pps_threshold=3,
            high_pps_threshold=10,
            critical_pps_threshold=20,
            minimum_syn_count=3,
        )
        timestamp = datetime.now(timezone.utc)

        first = detector.detect(
            packets_at(tcp_syn_same_service(4), timestamp),
            window_sec=10,
        )
        second = detector.detect(
            packets_at(tcp_syn_same_service(4), timestamp),
            window_sec=10,
        )
        third = detector.detect(
            packets_at(tcp_syn_same_service(4), timestamp + timedelta(seconds=1)),
            window_sec=10,
        )

        self.assertEqual(first, [])
        self.assertEqual(second, [])
        self.assertEqual(third[0]["evidence"]["exceeded_windows"], 2)

    def test_split_syn_multi_service_bucket_is_aggregated_across_ports(self):
        detector = SynFloodDetector(
            pps_threshold=4,
            high_pps_threshold=20,
            critical_pps_threshold=50,
            max_unique_ports=2,
            minimum_syn_count=4,
            required_exceeded_windows=1,
        )
        timestamp = datetime.now(timezone.utc)
        first_packets = []
        second_packets = []
        for dst_port in (80, 443):
            first_packets.extend(tcp_syn_same_service(2, dst_port=dst_port))
        for dst_port in (8080, 8443):
            second_packets.extend(tcp_syn_same_service(2, dst_port=dst_port))

        first = detector.detect(packets_at(first_packets, timestamp), window_sec=10)
        second = detector.detect(packets_at(second_packets, timestamp), window_sec=10)

        self.assertEqual(first, [])
        self.assertEqual(second[0]["detection_rule"], "tcp_syn_multi_service_rate")
        self.assertEqual(second[0]["evidence"]["syn_count"], 8)
        self.assertEqual(second[0]["evidence"]["unique_dst_port_count"], 4)

    def test_syn_burst_is_not_diluted_by_long_analysis_window(self):
        detector = SynFloodDetector(
            pps_threshold=120,
            high_pps_threshold=400,
            critical_pps_threshold=800,
            minimum_syn_count=30,
            required_exceeded_windows=1,
        )
        timestamp = datetime.now(timezone.utc)
        packets = tcp_syn_same_service(1000)
        for packet in packets:
            packet["timestamp"] = timestamp

        alerts = detector.detect(packets, window_sec=10)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"]["syn_pps"], 1000)
        self.assertEqual(alerts[0]["evidence"]["window_seconds"], 1.0)
        self.assertEqual(alerts[0]["severity"], "critical")


class SecurityEventBuilderTest(unittest.TestCase):
    def test_all_detection_modules_are_importable(self):
        from analyzer.app.detection.flood import IcmpFloodDetector
        from analyzer.app.detection.port_scan import PortScanDetector
        from analyzer.app.detection.syn_flood import SynFloodDetector

        self.assertIsNotNone(IcmpFloodDetector)
        self.assertIsNotNone(PortScanDetector)
        self.assertIsNotNone(SynFloodDetector)

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

    def test_detection_with_invalid_ip_is_not_converted_to_event(self):
        builder = SecurityEventBuilder()
        detection = {
            "src_ip": "abc",
            "dst_ip": "999.999.999.999",
            "protocol": "UDP",
            "attack_category": "FLOOD",
            "attack_type": "UDP_FLOOD",
            "severity": "high",
            "confidence": "high",
            "detection_rule": "udp_flood_rate_threshold",
            "recommended_action": "rate_limit",
            "response_level": "L2",
            "score": 80,
        }

        events = builder.build_security_events({"window_sec": 1}, [detection])

        self.assertEqual(events["events"], [])

    def test_unsupported_protocol_is_not_converted_to_security_event(self):
        builder = SecurityEventBuilder()
        detection = {
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.4",
            "protocol": "ARP",
            "attack_category": "FLOOD",
            "attack_type": "UDP_FLOOD",
            "severity": "high",
            "confidence": "high",
            "detection_rule": "unsupported_protocol_guard",
            "recommended_action": "rate_limit",
            "response_level": "L2",
            "score": 80,
        }

        events = builder.build_security_events({"window_sec": 1}, [detection])

        self.assertEqual(events["events"], [])

    def test_ipv6_detection_is_not_converted_to_ipv4_flow_rule(self):
        builder = SecurityEventBuilder()
        detection = {
            "src_ip": "2001:db8::1",
            "dst_ip": "2001:db8::2",
            "protocol": "UDP",
            "attack_category": "FLOOD",
            "attack_type": "UDP_FLOOD",
            "severity": "high",
            "confidence": "high",
            "detection_rule": "udp_flood_rate_threshold",
            "recommended_action": "rate_limit",
            "response_level": "L2",
            "score": 80,
        }

        events = builder.build_security_events({"window_sec": 1}, [detection])

        self.assertEqual(events["events"], [])

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
            queue.payload(
                timestamp="2026-07-10T00:00:00+00:00",
                analyzer_id="a1",
                events=queue.peek_batch(1),
            ),
            {
                "timestamp": "2026-07-10T00:00:00+00:00",
                "analyzer_id": "a1",
                "events": [second],
            },
        )
        queue.remove_sent([second])
        self.assertEqual(queue.payload(timestamp="t", analyzer_id="a")["events"], [third])
        self.assertEqual(queue.dropped_count, 1)

        queue.clear()
        self.assertEqual(len(queue), 0)

    def test_dead_letter_event_is_not_requeued(self):
        queue = PendingSecurityEventQueue(max_size=10)
        failed = {
            "event_id": "evt-1",
            "event_fingerprint": "fingerprint-1",
            "dedup_key": "fingerprint-1",
        }
        regenerated = {
            "event_id": "evt-2",
            "event_fingerprint": "fingerprint-1",
            "dedup_key": "fingerprint-1",
        }

        queue.add([failed])
        queue.move_to_dead_letter([failed], "HTTP 422")
        queue.add([regenerated])

        self.assertEqual(len(queue), 0)
        self.assertEqual(queue.dead_letter_count, 1)
        self.assertEqual(queue.last_dead_letter_event_id, "evt-1")
        self.assertEqual(queue.last_dead_letter_reason, "HTTP 422")

    def test_dead_letter_event_can_be_requeued_after_ttl(self):
        queue = PendingSecurityEventQueue(max_size=10, dead_letter_ttl_sec=0)
        failed = {
            "event_id": "evt-1",
            "event_fingerprint": "fingerprint-1",
            "dedup_key": "fingerprint-1",
        }
        regenerated = {
            "event_id": "evt-2",
            "event_fingerprint": "fingerprint-1",
            "dedup_key": "fingerprint-1",
        }

        queue.add([failed])
        queue.move_to_dead_letter([failed], "HTTP 422")
        queue.add([regenerated])

        self.assertEqual(queue.payload(timestamp="t", analyzer_id="a")["events"], [regenerated])


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

    def test_invalid_trusted_source_ip_is_rejected(self):
        with patch.dict(
            "os.environ",
            {"SECURITY_TRUSTED_SOURCE_IPS": "10.0.0.3,not-an-ip"},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "SECURITY_TRUSTED_SOURCE_IPS"):
                load_config()

    def test_ipv6_trusted_source_ip_is_rejected(self):
        with patch.dict(
            "os.environ",
            {"SECURITY_TRUSTED_SOURCE_IPS": "2001:db8::1"},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "SECURITY_TRUSTED_SOURCE_IPS"):
                load_config()

    def test_invalid_packet_buffer_size_is_rejected(self):
        with patch.dict(
            "os.environ",
            {"ANALYZER_PACKET_BUFFER_MAX_SIZE": "0"},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "ANALYZER_PACKET_BUFFER_MAX_SIZE"):
                load_config()

    def test_too_long_analyzer_id_is_rejected(self):
        with patch.dict("os.environ", {"ANALYZER_ID": "a" * 31}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "ANALYZER_ID"):
                load_config()

    def test_too_long_interface_name_is_rejected(self):
        with patch.dict(
            "os.environ",
            {"ANALYZER_INTERFACE": "eth" + "x" * 30},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "ANALYZER_INTERFACE"):
                load_config()


if __name__ == "__main__":
    unittest.main()
