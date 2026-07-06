from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
from typing import Any


class SecurityEventBuilder:
    def __init__(
        self,
        analyzer_id: str = "analyzer-1",
        icmp_pps_threshold: float = 1000,
    ):
        self.analyzer_id = analyzer_id
        self.icmp_pps_threshold = icmp_pps_threshold

    def build_security_events(
        self,
        packet_summary: dict[str, Any],
        packets: list[dict[str, Any]],
        port_scan_alerts: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()
        window_sec = packet_summary.get("window_sec", 1)

        events = []
        events.extend(
            self._build_port_scan_events(
                timestamp=timestamp,
                window_sec=window_sec,
                alerts=port_scan_alerts or [],
            )
        )
        events.extend(
            self._build_flood_events(
                timestamp=timestamp,
                window_sec=window_sec,
                packets=packets,
            )
        )

        return {
            "timestamp": timestamp,
            "analyzer_id": self.analyzer_id,
            "events": events,
        }

    def _build_port_scan_events(
        self,
        *,
        timestamp: str,
        window_sec: int | float,
        alerts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        events = []

        for alert in alerts:
            src_ip = alert.get("ip") or alert.get("src_ip")
            dst_ip = alert.get("target_ip") or alert.get("dst_ip")
            if not src_ip or not dst_ip:
                continue

            unique_port_count = int(alert.get("unique_dst_port_count") or 0)
            events.append(
                self._event(
                    timestamp=timestamp,
                    attack_category="RECON",
                    attack_type="PORT_SCAN",
                    severity="medium",
                    confidence="high",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="TCP",
                    detection_rule="tcp_syn_unique_ports",
                    recommended_action="monitor",
                    response_level="L1",
                    evidence={
                        "window_seconds": window_sec,
                        "unique_dst_port_count": unique_port_count,
                    },
                )
            )

        return events

    def _build_flood_events(
        self,
        *,
        timestamp: str,
        window_sec: int | float,
        packets: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        grouped = defaultdict(lambda: {"packets": 0})

        for packet in packets:
            protocol = packet.get("protocol")
            if protocol != "ICMP":
                continue

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            if not src_ip or not dst_ip:
                continue

            key = (protocol, src_ip, dst_ip)
            grouped[key]["packets"] += 1

        events = []
        divisor = window_sec if window_sec > 0 else 1

        for (protocol, src_ip, dst_ip), stats in grouped.items():
            pps = stats["packets"] / divisor

            if protocol == "ICMP" and pps >= self.icmp_pps_threshold:
                events.append(
                    self._event(
                        timestamp=timestamp,
                        attack_category="DDOS",
                        attack_type="ICMP_FLOOD",
                        severity="high",
                        confidence="medium",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="ICMP",
                        detection_rule="icmp_pps_threshold",
                        recommended_action="rate_limit",
                        response_level="L2",
                        evidence={
                            "window_seconds": window_sec,
                            "packet_count": stats["packets"],
                            "pps": pps,
                            "pps_threshold": self.icmp_pps_threshold,
                        },
                    )
                )

        return events

    def _event(
        self,
        *,
        timestamp: str,
        attack_category: str,
        attack_type: str,
        severity: str,
        confidence: str,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        detection_rule: str,
        recommended_action: str,
        response_level: str,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "event_id": _event_id(
                self.analyzer_id,
                attack_type,
                src_ip,
                dst_ip,
                protocol,
                detection_rule,
            ),
            "timestamp": timestamp,
            "analyzer_id": self.analyzer_id,
            "attack_category": attack_category,
            "attack_type": attack_type,
            "severity": severity,
            "confidence": confidence,
            "status": "detected",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "detection_rule": detection_rule,
            "recommended_action": recommended_action,
            "response_level": response_level,
            "evidence": evidence,
            "mitigation": None,
        }


def _event_id(*parts: str) -> str:
    raw = "|".join(parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"evt-{digest}"
