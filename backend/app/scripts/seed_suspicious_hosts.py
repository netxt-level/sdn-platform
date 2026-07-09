from datetime import datetime, timezone
from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parents[2]
sys.path.append(str(BACKEND_DIR))

from app.db.influxdb import write_detection_summary
from app.db.elasticsearch import index_security_event


def build_dummy_detection_summary() -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "analyzer_id": "analyzer-1",
        "network_status": "warning",
        "total_bps": 7_350_000.0,
        "total_pps": 1_420.0,
        "active_flow_count": 37,
    }


def build_dummy_security_events() -> list[dict]:
    timestamp = datetime.now(timezone.utc).isoformat()
    return [
        {
            "event_id": "seed-port-scan-001",
            "event_fingerprint": "fp-seed-port-scan-001",
            "dedup_key": "fp-seed-port-scan-001",
            "timestamp": timestamp,
            "analyzer_id": "analyzer-1",
            "attack_category": "RECON",
            "attack_type": "PORT_SCAN",
            "severity": "medium",
            "confidence": "high",
            "status": "detected",
            "src_ip": "10.0.0.11",
            "dst_ip": "10.0.0.4",
            "protocol": "TCP",
            "detection_rule": "tcp_syn_unique_ports",
            "recommended_action": "alert",
            "response_level": "L2",
            "evidence": {
                "matched_conditions": [
                    "tcp_syn_without_ack",
                    "same_source_target_pair",
                    "unique_dst_port_threshold_exceeded",
                    "syn_count_threshold_satisfied",
                ],
                "window_seconds": 5,
                "unique_dst_port_count": 24,
                "unique_dst_ports": list(range(1, 25)),
                "syn_count": 24,
                "score": 70,
            },
            "mitigation": None,
        },
        {
            "event_id": "seed-icmp-flood-001",
            "event_fingerprint": "fp-seed-icmp-flood-001",
            "dedup_key": "fp-seed-icmp-flood-001",
            "timestamp": timestamp,
            "analyzer_id": "analyzer-1",
            "attack_category": "FLOOD",
            "attack_type": "ICMP_FLOOD",
            "severity": "high",
            "confidence": "medium",
            "status": "detected",
            "src_ip": "10.0.0.23",
            "dst_ip": "10.0.0.5",
            "protocol": "ICMP",
            "detection_rule": "icmp_pps_threshold",
            "recommended_action": "rate_limit",
            "response_level": "L2",
            "evidence": {
                "matched_conditions": [
                    "icmp_protocol",
                    "same_source_target_pair",
                    "icmp_pps_threshold_exceeded",
                    "min_packet_count_satisfied",
                ],
                "window_seconds": 1,
                "packet_count": 1200,
                "pps": 1200.0,
                "pps_threshold": 1000,
                "min_packet_count": 1000,
                "high_pps_threshold": 3000,
                "score": 80,
            },
            "mitigation": {
                "action": "RATE_LIMIT",
                "target": "flow",
                "match": {
                    "eth_type": 2048,
                    "ipv4_src": "10.0.0.23",
                    "ipv4_dst": "10.0.0.5",
                    "ip_proto": 1,
                },
                "priority": 500,
                "idle_timeout": 60,
                "hard_timeout": 300,
                "rate_limit_pps": 100,
            },
        },
        {
            "event_id": "seed-arp-spoofing-001",
            "event_fingerprint": "fp-seed-arp-spoofing-001",
            "dedup_key": "fp-seed-arp-spoofing-001",
            "timestamp": timestamp,
            "analyzer_id": "analyzer-1",
            "attack_category": "L2_SPOOFING",
            "attack_type": "ARP_SPOOFING",
            "severity": "critical",
            "confidence": "high",
            "status": "detected",
            "src_ip": None,
            "src_mac": "00:00:00:00:00:66",
            "dst_ip": "10.0.0.11",
            "protocol": "ARP",
            "detection_rule": "trusted_gateway_mac_mismatch",
            "recommended_action": "block",
            "response_level": "L3",
            "evidence": {
                "matched_conditions": [
                    "arp_reply",
                    "sender_ip_matches_gateway",
                    "sender_mac_mismatch",
                ],
                "gateway_ip": "10.0.0.1",
                "trusted_gateway_mac": "00:00:00:00:00:01",
                "observed_sender_mac": "00:00:00:00:00:66",
                "score": 100,
            },
            "mitigation": {
                "action": "DROP",
                "target": "flow",
                "match": {
                    "eth_type": 2054,
                    "eth_src": "00:00:00:00:00:66",
                    "arp_spa": "10.0.0.1",
                },
                "priority": 650,
                "idle_timeout": 60,
                "hard_timeout": 300,
            },
        },
    ]


def main() -> None:
    detection_summary = build_dummy_detection_summary()
    write_detection_summary(detection_summary)
    events = build_dummy_security_events()
    for event in events:
        index_security_event(event)
    print(f"Inserted {len(events)} dummy security events.")


if __name__ == "__main__":
    main()
