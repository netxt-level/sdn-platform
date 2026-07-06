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
        icmp_min_packet_count: int = 1000,
        icmp_high_pps_threshold: float = 3000,
        icmp_high_pps_multiplier: float = 3.0,
        icmp_baseline_spike_multiplier: float = 5.0,
        icmp_baseline_min_pps: float = 100,
        icmp_alert_cooldown_sec: int = 60,
        rate_limit_priority: int = 500,
        rate_limit_idle_timeout: int = 60,
        rate_limit_hard_timeout: int = 300,
        rate_limit_pps: int = 100,
    ):
        self.analyzer_id = analyzer_id
        self.icmp_pps_threshold = icmp_pps_threshold
        self.icmp_min_packet_count = icmp_min_packet_count
        self.icmp_high_pps_threshold = icmp_high_pps_threshold
        self.icmp_high_pps_multiplier = icmp_high_pps_multiplier
        self.icmp_baseline_spike_multiplier = icmp_baseline_spike_multiplier
        self.icmp_baseline_min_pps = icmp_baseline_min_pps
        self.icmp_alert_cooldown_sec = icmp_alert_cooldown_sec
        self.rate_limit_priority = rate_limit_priority
        self.rate_limit_idle_timeout = rate_limit_idle_timeout
        self.rate_limit_hard_timeout = rate_limit_hard_timeout
        self.rate_limit_pps = rate_limit_pps

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
            unique_dst_ports = alert.get("unique_dst_ports") or []
            matched_conditions = alert.get("matched_conditions") or [
                "tcp_syn_without_ack",
                "same_source_target_pair",
                "unique_dst_port_threshold_exceeded",
            ]
            score = int(alert.get("score") or 60)
            recommended_action = alert.get("recommended_action") or "monitor"
            response_level = alert.get("response_level") or "L1"
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
                    recommended_action=recommended_action,
                    response_level=response_level,
                    evidence={
                        "matched_conditions": matched_conditions,
                        "window_seconds": alert.get("window_seconds") or window_sec,
                        "unique_dst_port_count": unique_port_count,
                        "unique_dst_ports": unique_dst_ports,
                        "syn_count": int(alert.get("syn_count") or 0),
                        "score": score,
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
            packet_count = stats["packets"]
            pps = stats["packets"] / divisor

            if protocol == "ICMP" and pps >= self.icmp_pps_threshold:
                matched_conditions = [
                    "icmp_protocol",
                    "same_source_target_pair",
                    "icmp_pps_threshold_exceeded",
                ]
                score = 60

                if packet_count >= self.icmp_min_packet_count:
                    matched_conditions.append("min_packet_count_satisfied")
                    score += 20

                high_pps_threshold = min(
                    self.icmp_high_pps_threshold,
                    self.icmp_pps_threshold * self.icmp_high_pps_multiplier,
                )
                if pps >= high_pps_threshold:
                    matched_conditions.append("high_pps_exceeded")
                    score += 15

                score = min(score, 100)
                is_l2 = score >= 80
                severity = "high" if is_l2 else "medium"
                confidence = "high" if score >= 95 else "medium"
                recommended_action = "rate_limit" if is_l2 else "monitor"
                response_level = "L2" if is_l2 else "L1"
                mitigation = (
                    self._rate_limit_mitigation(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                    )
                    if is_l2
                    else None
                )

                events.append(
                    self._event(
                        timestamp=timestamp,
                        attack_category="DDOS",
                        attack_type="ICMP_FLOOD",
                        severity=severity,
                        confidence=confidence,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="ICMP",
                        detection_rule="icmp_pps_threshold",
                        recommended_action=recommended_action,
                        response_level=response_level,
                        evidence={
                            "matched_conditions": matched_conditions,
                            "window_seconds": window_sec,
                            "packet_count": packet_count,
                            "pps": pps,
                            "pps_threshold": self.icmp_pps_threshold,
                            "min_packet_count": self.icmp_min_packet_count,
                            "high_pps_threshold": high_pps_threshold,
                            "score": score,
                        },
                        mitigation=mitigation,
                    )
                )

        return events

    def _rate_limit_mitigation(self, *, src_ip: str, dst_ip: str) -> dict[str, Any]:
        return {
            "action": "RATE_LIMIT",
            "target": "flow",
            "match": {
                "eth_type": 2048,
                "ipv4_src": src_ip,
                "ipv4_dst": dst_ip,
                "ip_proto": 1,
            },
            "priority": self.rate_limit_priority,
            "idle_timeout": self.rate_limit_idle_timeout,
            "hard_timeout": self.rate_limit_hard_timeout,
            "rate_limit_pps": self.rate_limit_pps,
        }

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
        mitigation: dict[str, Any] | None = None,
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
            "mitigation": mitigation,
        }


def _event_id(*parts: str) -> str:
    raw = "|".join(parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"evt-{digest}"
