from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
from typing import Any


class SecurityEventBuilder:
    """패킷과 탐지 경고를 공통 보안 이벤트 형식으로 변환한다.

    이 클래스는 공격 여부와 대응 후보까지만 결정한다. 실제 스위치 반영은
    백엔드가 생성한 PENDING Flow Rule을 Controller가 처리하는 단계에서
    이루어진다.
    """

    def __init__(
        self,
        analyzer_id: str = "analyzer-1",
        gateway_ip: str = "10.0.0.254",
        gateway_mac: str = "00:00:00:00:ff:ff",
        arp_drop_priority: int = 650,
        arp_drop_idle_timeout: int = 60,
        arp_drop_hard_timeout: int = 300,
        icmp_pps_threshold: float = 1000,
        icmp_min_packet_count: int = 1000,
        icmp_high_pps_threshold: float = 3000,
        icmp_high_pps_multiplier: float = 3.0,
        event_dedup_window_sec: int = 60,
        rate_limit_priority: int = 500,
        rate_limit_idle_timeout: int = 60,
        rate_limit_hard_timeout: int = 300,
        rate_limit_pps: int = 100,
    ):
        self.analyzer_id = analyzer_id
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac.lower()
        self.arp_drop_priority = arp_drop_priority
        self.arp_drop_idle_timeout = arp_drop_idle_timeout
        self.arp_drop_hard_timeout = arp_drop_hard_timeout
        self.icmp_pps_threshold = icmp_pps_threshold
        self.icmp_min_packet_count = icmp_min_packet_count
        self.icmp_high_pps_threshold = icmp_high_pps_threshold
        self.icmp_high_pps_multiplier = icmp_high_pps_multiplier
        self.event_dedup_window_sec = event_dedup_window_sec
        self.rate_limit_priority = rate_limit_priority
        self.rate_limit_idle_timeout = rate_limit_idle_timeout
        self.rate_limit_hard_timeout = rate_limit_hard_timeout
        self.rate_limit_pps = rate_limit_pps
        self.recent_events: dict[str, dict[str, Any]] = {}

    def build_security_events(
        self,
        packet_summary: dict[str, Any],
        packets: list[dict[str, Any]],
        port_scan_alerts: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        self._expire_recent_events(now)
        timestamp = now.isoformat()
        window_sec = packet_summary.get("window_sec", 1)
        event_window_sec = window_sec if window_sec > 0 else 1
        window_start_epoch = int(
            now.timestamp() // event_window_sec * event_window_sec
        )

        events = []
        events.extend(
            self._build_arp_spoofing_events(
                timestamp=timestamp,
                now=now,
                window_start_epoch=window_start_epoch,
                packets=packets,
            )
        )
        events.extend(
            self._build_port_scan_events(
                timestamp=timestamp,
                now=now,
                window_sec=window_sec,
                window_start_epoch=window_start_epoch,
                alerts=port_scan_alerts or [],
            )
        )
        events.extend(
            self._build_flood_events(
                timestamp=timestamp,
                now=now,
                window_sec=window_sec,
                window_start_epoch=window_start_epoch,
                packets=packets,
            )
        )

        return {
            "timestamp": timestamp,
            "analyzer_id": self.analyzer_id,
            "events": events,
        }

    def _build_arp_spoofing_events(
        self,
        *,
        timestamp: str,
        now: datetime,
        window_start_epoch: int,
        packets: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """게이트웨이 IP를 다른 MAC이 주장하는 ARP Reply를 찾는다.

        신뢰 MAC이 없는 일반 IP의 중복 매핑은 어느 쪽이 공격자인지 판단할
        근거가 부족하므로 자동 DROP 대상으로 만들지 않는다.
        """

        events = []

        for packet in packets:
            if packet.get("protocol") != "ARP":
                continue
            if str(packet.get("arp_opcode") or "").lower() not in {"reply", "2"}:
                continue

            claimed_ip = str(packet.get("arp_sender_ip") or packet.get("src_ip") or "")
            claimed_mac = str(packet.get("arp_sender_mac") or "").lower()
            ethernet_src_mac = str(packet.get("src_mac") or claimed_mac).lower()
            target_ip = str(packet.get("arp_target_ip") or packet.get("dst_ip") or "")

            if claimed_ip != self.gateway_ip or not claimed_mac:
                continue
            if claimed_mac == self.gateway_mac:
                continue

            matched_conditions = [
                "arp_reply",
                "gateway_ip_claimed",
                "gateway_mac_mismatch",
            ]
            event = self._event(
                timestamp=timestamp,
                attack_category="L2_SPOOFING",
                attack_type="ARP_SPOOFING",
                severity="critical",
                confidence="high",
                src_ip=None,
                src_mac=ethernet_src_mac or claimed_mac,
                dst_ip=target_ip or self.gateway_ip,
                protocol="ARP",
                detection_rule="trusted_gateway_mac_mismatch",
                recommended_action="block",
                response_level="L3",
                evidence={
                    "matched_conditions": matched_conditions,
                    "spoofed_ip": claimed_ip,
                    "trusted_mac": self.gateway_mac,
                    "claimed_mac": claimed_mac,
                    "ethernet_src_mac": ethernet_src_mac,
                    "arp_target_ip": target_ip,
                    "arp_target_mac": packet.get("arp_target_mac") or "",
                    "arp_opcode": packet.get("arp_opcode"),
                    "score": 100,
                },
                mitigation=self._arp_drop_mitigation(
                    attacker_mac=ethernet_src_mac or claimed_mac,
                    spoofed_ip=claimed_ip,
                ),
                now=now,
                window_start_epoch=window_start_epoch,
            )
            if event is not None:
                events.append(event)

        return events

    def _build_port_scan_events(
        self,
        *,
        timestamp: str,
        now: datetime,
        window_sec: int | float,
        window_start_epoch: int,
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
            event = self._event(
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
                now=now,
                window_start_epoch=window_start_epoch,
            )
            if event is not None:
                events.append(event)

        return events

    def _build_flood_events(
        self,
        *,
        timestamp: str,
        now: datetime,
        window_sec: int | float,
        window_start_epoch: int,
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

                event = self._event(
                    timestamp=timestamp,
                    attack_category="FLOOD",
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
                    now=now,
                    window_start_epoch=window_start_epoch,
                )
                if event is not None:
                    events.append(event)

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

    def _arp_drop_mitigation(
        self,
        *,
        attacker_mac: str,
        spoofed_ip: str,
    ) -> dict[str, Any]:
        """위조 ARP만 좁게 차단하는 OpenFlow 후보를 만든다."""

        return {
            "action": "DROP",
            "target": "flow",
            "match": {
                "eth_type": 2054,
                "eth_src": attacker_mac,
                "arp_spa": spoofed_ip,
            },
            "priority": self.arp_drop_priority,
            "idle_timeout": self.arp_drop_idle_timeout,
            "hard_timeout": self.arp_drop_hard_timeout,
        }

    def _event(
        self,
        *,
        timestamp: str,
        attack_category: str,
        attack_type: str,
        severity: str,
        confidence: str,
        src_ip: str | None,
        src_mac: str | None = None,
        dst_ip: str,
        protocol: str,
        detection_rule: str,
        recommended_action: str,
        response_level: str,
        evidence: dict[str, Any],
        mitigation: dict[str, Any] | None = None,
        now: datetime,
        window_start_epoch: int,
    ) -> dict[str, Any] | None:
        event_fingerprint = _event_fingerprint(
            self.analyzer_id,
            attack_type,
            src_ip or "",
            src_mac or "",
            dst_ip,
            protocol,
            detection_rule,
        )
        dedup_key = event_fingerprint

        if self._is_duplicate(
            dedup_key=dedup_key,
            now=now,
            severity=severity,
            response_level=response_level,
        ):
            return None

        self.recent_events[dedup_key] = {
            "timestamp": now,
            "severity": severity,
            "response_level": response_level,
        }

        return {
            "event_id": _event_id(event_fingerprint, str(window_start_epoch)),
            "event_fingerprint": event_fingerprint,
            "dedup_key": dedup_key,
            "timestamp": timestamp,
            "analyzer_id": self.analyzer_id,
            "attack_category": attack_category,
            "attack_type": attack_type,
            "severity": severity,
            "confidence": confidence,
            "status": "detected",
            "src_ip": src_ip,
            "src_mac": src_mac,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "detection_rule": detection_rule,
            "recommended_action": recommended_action,
            "response_level": response_level,
            "evidence": evidence,
            "mitigation": mitigation,
        }

    def _is_duplicate(
        self,
        *,
        dedup_key: str,
        now: datetime,
        severity: str,
        response_level: str,
    ) -> bool:
        last_event = self.recent_events.get(dedup_key)
        if last_event is None:
            return False

        elapsed = (now - last_event["timestamp"]).total_seconds()
        if elapsed >= self.event_dedup_window_sec:
            return False

        if _policy_rank(response_level) > _policy_rank(last_event["response_level"]):
            return False

        if _severity_rank(severity) > _severity_rank(last_event["severity"]):
            return False

        return True

    def _expire_recent_events(self, now: datetime) -> None:
        """중복 억제 시간이 지난 fingerprint를 제거해 메모리 증가를 막는다."""

        expired_keys = [
            key
            for key, event in self.recent_events.items()
            if (now - event["timestamp"]).total_seconds()
            >= self.event_dedup_window_sec
        ]
        for key in expired_keys:
            self.recent_events.pop(key, None)


def _event_id(*parts: str) -> str:
    raw = "|".join(parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"evt-{digest}"


def _event_fingerprint(*parts: str) -> str:
    raw = "|".join(parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _policy_rank(value: str) -> int:
    return {
        "L1": 1,
        "L2": 2,
        "L3": 3,
    }.get(value, 0)


def _severity_rank(value: str) -> int:
    return {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }.get(value, 0)
