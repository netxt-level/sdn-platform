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
            "recommended_action": "monitor",
            "response_level": "L1",
            "evidence": {
                "window_seconds": 5,
                "unique_dst_port_count": 24,
            },
            "mitigation": None,
        },
        {
            "event_id": "seed-udp-flood-001",
            "timestamp": timestamp,
            "analyzer_id": "analyzer-1",
            "attack_category": "DDOS",
            "attack_type": "UDP_FLOOD",
            "severity": "high",
            "confidence": "medium",
            "status": "detected",
            "src_ip": "10.0.0.23",
            "dst_ip": "10.0.0.5",
            "protocol": "UDP",
            "detection_rule": "udp_pps_or_bps_threshold",
            "recommended_action": "rate_limit",
            "response_level": "L2",
            "evidence": {
                "window_seconds": 1,
                "pps": 510.0,
                "bps": 3_900_000.0,
                "pps_threshold": 1000,
                "bps_threshold": 5_000_000,
            },
            "mitigation": None,
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
