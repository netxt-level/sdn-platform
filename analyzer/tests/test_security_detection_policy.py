import json
from pathlib import Path
import unittest

from analyzer.app.detection.port_scan import PortScanDetector
from analyzer.app.detection.security_events import SecurityEventBuilder


def tcp_syn_packets(src_ip="10.0.0.2", dst_ip="10.0.0.4", ports=range(1, 21)):
    return [
        {
            "protocol": "TCP",
            "tcp_flags": "S",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": port,
        }
        for port in ports
    ]


def icmp_packets(count, src_ip="10.0.0.2", dst_ip="10.0.0.4"):
    return [
        {
            "protocol": "ICMP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        }
        for _ in range(count)
    ]


def arp_reply(
    *,
    sender_ip="10.0.0.254",
    sender_mac="00:00:00:00:00:02",
    target_ip="10.0.0.1",
    ethernet_src=None,
    opcode="reply",
):
    return {
        "protocol": "ARP",
        "src_mac": ethernet_src or sender_mac,
        "dst_mac": "ff:ff:ff:ff:ff:ff",
        "arp_opcode": opcode,
        "arp_sender_ip": sender_ip,
        "arp_sender_mac": sender_mac,
        "arp_target_ip": target_ip,
        "arp_target_mac": "00:00:00:00:00:01",
    }


class ArpSpoofingDetectionPolicyTest(unittest.TestCase):
    def test_final_scenario_sample_builds_arp_spoofing_event(self):
        sample_path = (
            Path(__file__).resolve().parents[2]
            / "samples"
            / "security_scenario_06_arp_spoofing_final.json"
        )
        sample = json.loads(sample_path.read_text(encoding="utf-8"))
        builder = SecurityEventBuilder(**sample["security_config"])

        result = builder.build_security_events(
            sample["packet_summary"],
            sample["packets"],
        )

        self.assertEqual(
            [event["attack_type"] for event in result["events"]],
            ["ARP_SPOOFING"],
        )

    def test_trusted_gateway_reply_is_not_detected(self):
        builder = SecurityEventBuilder()

        result = builder.build_security_events(
            {"window_sec": 1},
            [arp_reply(sender_mac="00:00:00:00:ff:ff")],
        )

        self.assertEqual(result["events"], [])

    def test_gateway_request_is_not_treated_as_final_spoofing_scenario(self):
        builder = SecurityEventBuilder()

        result = builder.build_security_events(
            {"window_sec": 1},
            [arp_reply(opcode="request")],
        )

        self.assertEqual(result["events"], [])

    def test_unknown_ip_mapping_does_not_create_automatic_drop(self):
        builder = SecurityEventBuilder()

        result = builder.build_security_events(
            {"window_sec": 1},
            [
                arp_reply(
                    sender_ip="10.0.0.10",
                    sender_mac="00:00:00:00:00:01",
                ),
                arp_reply(
                    sender_ip="10.0.0.10",
                    sender_mac="00:00:00:00:00:02",
                ),
            ],
        )

        self.assertEqual(result["events"], [])

    def test_gateway_mac_mismatch_builds_critical_drop_candidate(self):
        builder = SecurityEventBuilder()

        event = builder.build_security_events(
            {"window_sec": 1},
            [arp_reply()],
        )["events"][0]

        self.assertEqual(event["attack_type"], "ARP_SPOOFING")
        self.assertEqual(event["attack_category"], "L2_SPOOFING")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(event["confidence"], "high")
        self.assertEqual(event["response_level"], "L3")
        self.assertIsNone(event["src_ip"])
        self.assertEqual(event["src_mac"], "00:00:00:00:00:02")
        self.assertEqual(event["dst_ip"], "10.0.0.1")
        self.assertEqual(event["evidence"]["spoofed_ip"], "10.0.0.254")
        self.assertEqual(event["evidence"]["trusted_mac"], "00:00:00:00:ff:ff")
        self.assertEqual(event["mitigation"]["action"], "DROP")
        self.assertEqual(
            event["mitigation"]["match"],
            {
                "eth_type": 2054,
                "eth_src": "00:00:00:00:00:02",
                "arp_spa": "10.0.0.254",
            },
        )


class PortScanDetectionPolicyTest(unittest.TestCase):
    def test_port_scan_below_unique_port_threshold_is_not_detected(self):
        detector = PortScanDetector()

        alerts = detector.detect(tcp_syn_packets(ports=range(1, 20)))

        self.assertEqual(alerts, [])

    def test_port_scan_l2_alert_contains_policy_evidence(self):
        detector = PortScanDetector()

        alert = detector.detect(tcp_syn_packets())[0]

        self.assertEqual(alert["response_level"], "L2")
        self.assertEqual(alert["recommended_action"], "alert")
        self.assertEqual(alert["score"], 70)
        self.assertEqual(alert["syn_count"], 20)
        self.assertEqual(len(alert["unique_dst_ports"]), 20)
        self.assertEqual(
            alert["matched_conditions"],
            [
                "tcp_syn_without_ack",
                "same_source_target_pair",
                "unique_dst_port_threshold_exceeded",
                "syn_count_threshold_satisfied",
            ],
        )

    def test_port_scan_security_event_includes_evidence(self):
        detector = PortScanDetector()
        alerts = detector.detect(tcp_syn_packets())
        builder = SecurityEventBuilder()

        event = builder.build_security_events(
            {"window_sec": 1},
            [],
            port_scan_alerts=alerts,
        )["events"][0]

        self.assertEqual(event["attack_type"], "PORT_SCAN")
        self.assertEqual(event["response_level"], "L2")
        self.assertEqual(event["recommended_action"], "alert")
        self.assertIsNone(event["mitigation"])
        self.assertEqual(event["evidence"]["score"], 70)
        self.assertEqual(event["evidence"]["syn_count"], 20)
        self.assertEqual(len(event["evidence"]["unique_dst_ports"]), 20)


class IcmpFloodDetectionPolicyTest(unittest.TestCase):
    def test_icmp_flood_l1_has_no_mitigation(self):
        builder = SecurityEventBuilder(
            icmp_pps_threshold=1000,
            icmp_min_packet_count=1200,
        )

        event = builder.build_security_events(
            {"window_sec": 1},
            icmp_packets(1000),
        )["events"][0]

        self.assertEqual(event["response_level"], "L1")
        self.assertEqual(event["recommended_action"], "monitor")
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(event["confidence"], "medium")
        self.assertIsNone(event["mitigation"])
        self.assertEqual(event["evidence"]["score"], 60)
        self.assertEqual(
            event["evidence"]["matched_conditions"],
            [
                "icmp_protocol",
                "same_source_target_pair",
                "icmp_pps_threshold_exceeded",
            ],
        )

    def test_icmp_flood_l2_includes_rate_limit_mitigation(self):
        builder = SecurityEventBuilder()

        event = builder.build_security_events(
            {"window_sec": 1},
            icmp_packets(1000),
        )["events"][0]

        self.assertEqual(event["response_level"], "L2")
        self.assertEqual(event["recommended_action"], "rate_limit")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["confidence"], "medium")
        self.assertEqual(event["evidence"]["score"], 80)
        self.assertEqual(event["mitigation"]["action"], "RATE_LIMIT")
        self.assertEqual(event["mitigation"]["match"]["ip_proto"], 1)
        self.assertEqual(event["mitigation"]["rate_limit_pps"], 100)

    def test_icmp_flood_high_pps_raises_confidence(self):
        builder = SecurityEventBuilder()

        event = builder.build_security_events(
            {"window_sec": 1},
            icmp_packets(3000),
        )["events"][0]

        self.assertEqual(event["response_level"], "L2")
        self.assertEqual(event["confidence"], "high")
        self.assertEqual(event["evidence"]["score"], 95)
        self.assertIn("high_pps_exceeded", event["evidence"]["matched_conditions"])


class SecurityEventDedupPolicyTest(unittest.TestCase):
    def test_event_identity_fields_are_included(self):
        builder = SecurityEventBuilder()

        event = builder.build_security_events(
            {"window_sec": 1},
            icmp_packets(1000),
        )["events"][0]

        self.assertTrue(event["event_id"].startswith("evt-"))
        self.assertEqual(len(event["event_id"]), 16)
        self.assertEqual(len(event["event_fingerprint"]), 40)
        self.assertEqual(event["dedup_key"], event["event_fingerprint"])

    def test_duplicate_event_is_suppressed_inside_dedup_window(self):
        builder = SecurityEventBuilder()

        first = builder.build_security_events({"window_sec": 1}, icmp_packets(1000))
        second = builder.build_security_events({"window_sec": 1}, icmp_packets(1000))

        self.assertEqual(len(first["events"]), 1)
        self.assertEqual(second["events"], [])

    def test_escalated_event_bypasses_dedup(self):
        builder = SecurityEventBuilder(
            icmp_pps_threshold=1000,
            icmp_min_packet_count=1200,
        )

        first = builder.build_security_events({"window_sec": 1}, icmp_packets(1000))
        second = builder.build_security_events({"window_sec": 1}, icmp_packets(1200))

        self.assertEqual(first["events"][0]["response_level"], "L1")
        self.assertEqual(len(second["events"]), 1)
        self.assertEqual(second["events"][0]["response_level"], "L2")


if __name__ == "__main__":
    unittest.main()
