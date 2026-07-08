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
