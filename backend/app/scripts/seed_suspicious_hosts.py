from datetime import datetime, timezone
from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parents[2]
sys.path.append(str(BACKEND_DIR))

from app.db.influxdb import write_detection_summary


def build_dummy_detection_summary() -> dict:
    suspicious_hosts = [
        {
            "host": "scanner-01",
            "ip": "10.0.0.11",
            "protocol": "TCP",
            "bps": 0.0,
            "pps": 0.0,
            "attack_type": "PORT_SCAN",
            "reasons": [
                "Port Scan",
            ],
        },
        {
            "host": "burst-client",
            "ip": "10.0.0.23",
            "protocol": "UDP",
            "bps": 3_900_000.0,
            "pps": 510.0,
            "attack_type": "DOS",
            "reasons": [
                "DoS",
            ],
        },
        {
            "host": "high-pps-host",
            "ip": "10.0.0.37",
            "protocol": "TCP",
            "bps": 650_000.0,
            "pps": 230.0,
            "attack_type": "DOS",
            "reasons": [
                "DoS",
            ],
        },
    ]

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "analyzer_id": "analyzer-1",
        "network_status": "warning",
        "total_bps": 7_350_000.0,
        "total_pps": 1_420.0,
        "active_flow_count": 37,
        "suspicious_host_count": len(suspicious_hosts),
        "suspicious_hosts": suspicious_hosts,
    }


def main() -> None:
    detection_summary = build_dummy_detection_summary()
    write_detection_summary(detection_summary)
    print(
        "Inserted "
        f"{detection_summary['suspicious_host_count']} dummy suspicious hosts."
    )


if __name__ == "__main__":
    main()
