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
                    "TCP SYN만 있고 ACK는 없음",
                    "출발지와 목적지 IP가 확인됨",
                    "고유 목적지 포트 수 기준 초과",
                    "SYN 시도 수 기준 초과",
                    "관리/서비스 포트 다수 포함",
                ],
                "window_seconds": 5,
                "unique_dst_port_count": 10,
                "unique_dst_ports": [1, 2, 3, 4, 5, 22, 23, 80, 443, 3389],
                "common_dst_ports": [22, 23, 80, 443, 3389],
                "syn_count": 10,
                "scanned_target_count": 1,
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
                    "ICMP 패킷",
                    "같은 출발지와 목적지 쌍",
                    "ICMP pps 기준 초과",
                    "최소 패킷 수 기준 초과",
                    "짧은 시간 패킷 수가 크게 증가",
                    "높은 pps 기준 초과",
                ],
                "window_seconds": 1,
                "packet_count": 300,
                "pps": 300.0,
                "pps_threshold": 100,
                "min_packet_count": 100,
                "high_pps_threshold": 300,
                "average_payload_size": 0,
                "large_payload_threshold": 512,
                "score": 95,
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
                    "ARP Reply 패킷",
                    "Gateway IP를 sender IP로 사용",
                    "신뢰 Gateway MAC과 다른 MAC 사용",
                    "ARP sender MAC 확인됨",
                    "Ethernet source MAC과 ARP sender MAC 일치",
                    "대상 호스트 IP 포함",
                ],
                "spoofed_ip": "10.0.0.254",
                "trusted_mac": "00:00:00:00:ff:ff",
                "claimed_mac": "00:00:00:00:00:66",
                "ethernet_src_mac": "00:00:00:00:00:66",
                "arp_target_ip": "10.0.0.11",
                "arp_target_mac": "00:00:00:00:00:11",
                "reply_count": 1,
                "score": 95,
            },
            "mitigation": {
                "action": "DROP",
                "target": "flow",
                "match": {
                    "eth_type": 2054,
                    "eth_src": "00:00:00:00:00:66",
                    "arp_spa": "10.0.0.254",
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
    print(f"샘플 보안 이벤트 {len(events)}건을 저장했습니다.")


if __name__ == "__main__":
    main()
