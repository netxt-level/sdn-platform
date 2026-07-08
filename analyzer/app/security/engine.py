from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
from typing import Iterable

from .baseline import BaselineProfile
from .models import (
    AnalysisResult,
    DetectionConfig,
    EventStatus,
    LinkState,
    MitigationAction,
    MitigationPolicy,
    PacketRecord,
    SecurityEvent,
)


class SecurityAnalysisEngine:
    """보안 담당 범위에 맞춘 최소 탐지 엔진.

    최종 시나리오는 ARP Spoofing이다. ICMP Flood와 Port Scan은 기존 브랜치의
    흐름을 참고하되, 발표 흐름을 보조하는 탐지 항목으로만 둔다. 그래서 이
    엔진은 필요한 세 가지 이벤트만 만든다.
    """

    def __init__(self, config: DetectionConfig | None = None, baseline: BaselineProfile | None = None) -> None:
        self.config = config or DetectionConfig()
        self.baseline = baseline

    def analyze(
        self,
        packets: Iterable[PacketRecord],
        links: Iterable[LinkState] | None = None,
        now: datetime | None = None,
    ) -> AnalysisResult:
        packet_list = list(packets)
        now = now or _analysis_time(packet_list)
        window_packets = self._select_window(packet_list, now)

        # links 인자는 컨트롤러/토폴로지 쪽 확장을 위해 남겨둔다.
        # 현재 보안 담당 범위에서는 링크 장애나 혼잡 이벤트를 만들지 않는다.
        _ = links

        events: list[SecurityEvent] = []
        events.extend(self._detect_arp_spoofing(window_packets, now))
        events.extend(self._detect_port_scan(window_packets, now))
        events.extend(self._detect_icmp_flood(window_packets, now))

        policies = [event.policy for event in events if event.policy is not None]
        return AnalysisResult(
            window_seconds=self.config.window_seconds,
            packet_count=sum(max(packet.packet_count, 1) for packet in window_packets),
            events=events,
            policies=policies,
        )

    def _select_window(self, packets: list[PacketRecord], now: datetime) -> list[PacketRecord]:
        if not packets:
            return []

        cutoff = now.timestamp() - self.config.window_seconds
        return [packet for packet in packets if packet.timestamp.timestamp() >= cutoff]

    def _detect_arp_spoofing(self, packets: list[PacketRecord], now: datetime) -> list[SecurityEvent]:
        # ARP Spoofing의 핵심은 "같은 IP가 원래 알고 있던 MAC과 다르게 보이는가"다.
        # Gateway IP/MAC은 config에서 우선 받고, 샘플이나 사전 학습값이 있으면 baseline도 참고한다.
        trusted = {ip: mac.lower() for ip, mac in self.config.trusted_ip_mac.items()}
        if self.config.gateway_ip and self.config.gateway_mac:
            trusted[self.config.gateway_ip] = self.config.gateway_mac.lower()
        if self.baseline:
            trusted = {**self.baseline.ip_mac, **trusted}

        observed: dict[str, set[str]] = defaultdict(set)
        arp_context: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: {"target_ips": set(), "target_macs": set(), "opcodes": set()}
        )

        for packet in packets:
            if packet.protocol_name != "ARP":
                continue

            sender_ip = packet.arp_sender_ip or packet.src_ip
            sender_mac = (packet.arp_sender_mac or packet.src_mac).lower()
            if not sender_ip or not sender_mac:
                continue

            # 한 윈도우 안에서 관측된 IP-MAC 매핑을 모아둔다.
            # 이후 정상 MAC과 다르거나, 하나의 IP에 MAC이 둘 이상 붙으면 위조 가능성으로 본다.
            observed[sender_ip].add(sender_mac)
            if packet.arp_target_ip:
                arp_context[sender_ip]["target_ips"].add(packet.arp_target_ip)
            if packet.arp_target_mac:
                arp_context[sender_ip]["target_macs"].add(packet.arp_target_mac.lower())
            if packet.arp_opcode:
                arp_context[sender_ip]["opcodes"].add(packet.arp_opcode.lower())

        events: list[SecurityEvent] = []
        for ip, macs in observed.items():
            trusted_mac = trusted.get(ip)
            duplicate_mapping = len(macs) >= 2
            trusted_mismatch = bool(trusted_mac and any(mac != trusted_mac for mac in macs))
            if not trusted_mismatch and not duplicate_mapping:
                continue

            attacker_mac = next((mac for mac in sorted(macs) if mac != trusted_mac), sorted(macs)[0])
            reason = "trusted_mac_mismatch" if trusted_mismatch else "duplicate_ip_mac_mapping"

            # ARP Spoofing은 근거가 명확한 편이라 위조 ARP sender만 DROP 후보로 만든다.
            # 전체 호스트를 막지 않고, 위조된 ARP 응답 조건만 좁게 잡는 것이 발표 설명에도 자연스럽다.
            policy = self._policy(
                MitigationAction.DROP,
                {"eth_type": "ARP", "arp_spa": ip, "eth_src": attacker_mac},
                650,
                "arp spoofing block",
            )
            events.append(
                self._event(
                    "ARP_SPOOFING",
                    "Critical",
                    dst_ip=ip,
                    src_mac=attacker_mac,
                    protocol="ARP",
                    metric_name="mac_mapping_count",
                    metric_value=len(macs),
                    threshold=1,
                    action=policy.action,
                    policy=policy,
                    evidence={
                        "spoofed_ip": ip,
                        "attacker_mac": attacker_mac,
                        "observed_macs": sorted(macs),
                        "trusted_mac": trusted_mac,
                        "detection_reason": reason,
                        "arp_target_ips": sorted(arp_context[ip]["target_ips"]),
                        "arp_target_macs": sorted(arp_context[ip]["target_macs"]),
                        "arp_opcodes": sorted(arp_context[ip]["opcodes"]),
                    },
                    now=now,
                )
            )

        return events

    def _detect_port_scan(self, packets: list[PacketRecord], now: datetime) -> list[SecurityEvent]:
        # Port Scan은 공격 전 정찰 행위에 가깝다.
        # 여기서는 ICMP/Port Scan 브랜치의 흐름을 참고하되, TCP SYN만 기준으로 좁혀서 본다.
        # SYN은 있고 ACK는 없는 패킷이 여러 목적지 포트로 퍼지면 "연결 시도만 던져보는" 패턴이 된다.
        ports_by_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
        syn_count_by_pair: dict[tuple[str, str], int] = defaultdict(int)

        for packet in packets:
            if packet.protocol_name != "TCP" or packet.dst_port is None:
                continue
            if not packet.src_ip or not packet.dst_ip or not packet.is_syn_only:
                continue

            key = (packet.src_ip, packet.dst_ip)
            ports_by_pair[key].add(packet.dst_port)
            syn_count_by_pair[key] += max(packet.packet_count, 1)

        events: list[SecurityEvent] = []
        for (src_ip, dst_ip), ports in ports_by_pair.items():
            port_count = len(ports)
            if port_count < self.config.port_scan_unique_ports:
                continue

            syn_count = syn_count_by_pair[(src_ip, dst_ip)]
            matched_conditions = [
                "tcp_syn_without_ack",
                "same_source_target_pair",
                "unique_dst_port_threshold_exceeded",
            ]
            score = 60
            if syn_count >= self.config.port_scan_unique_ports:
                matched_conditions.append("syn_count_threshold_satisfied")
                score += 10

            # Port Scan은 정상 점검 도구와 겹칠 여지가 있어 바로 DROP하지 않는다.
            # 대신 같은 출발지/목적지 TCP 흐름을 낮은 속도로 제한하는 후보 정책만 만든다.
            policy = self._policy(
                MitigationAction.RATE_LIMIT,
                {"ipv4_src": src_ip, "ipv4_dst": dst_ip, "ip_proto": "TCP"},
                350,
                "port scan source rate limit",
                rate_limit_pps=self.config.rate_limit_pps,
            )
            events.append(
                self._event(
                    "PORT_SCAN",
                    "Medium",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="TCP",
                    metric_name="unique_dst_ports",
                    metric_value=port_count,
                    threshold=self.config.port_scan_unique_ports,
                    action=policy.action,
                    policy=policy,
                    evidence={
                        "matched_conditions": matched_conditions,
                        "ports": sorted(ports)[:50],
                        "syn_count": syn_count,
                        "score": min(score, 100),
                        "response_level": "L2" if score >= 70 else "L1",
                        "recommended_action": "rate_limit" if score >= 70 else "monitor",
                        "window_seconds": self.config.window_seconds,
                    },
                    now=now,
                )
            )

        return events

    def _detect_icmp_flood(self, packets: list[PacketRecord], now: datetime) -> list[SecurityEvent]:
        # ICMP Flood는 "ping이 많다"만으로 단정하면 오탐이 생기기 쉽다.
        # 그래서 출발지/목적지 단위로 묶고, 절대 PPS 기준과 baseline 급증 기준을 함께 본다.
        grouped = _group_packets(packets, protocol="ICMP")
        events: list[SecurityEvent] = []

        for (src_ip, dst_ip), stats in grouped.items():
            min_required_packets = max(
                self.config.min_sample_packets,
                int(self.config.icmp_pps_threshold * self.config.window_seconds),
            )
            if stats["packets"] < min_required_packets:
                continue

            pps = stats["packets"] / self.config.window_seconds
            baseline = self._baseline_protocol_pps(src_ip, "ICMP")
            threshold = max(self.config.icmp_pps_threshold, baseline * self.config.baseline_multiplier)
            if pps < threshold:
                continue

            matched_conditions = [
                "icmp_protocol",
                "same_source_target_pair",
                "icmp_pps_threshold_exceeded",
                "min_packet_count_satisfied",
            ]
            score = 80
            high_pps_threshold = threshold * 3
            if pps >= high_pps_threshold:
                matched_conditions.append("high_pps_exceeded")
                score += 15
            if baseline > 0 and pps >= baseline * self.config.baseline_multiplier:
                matched_conditions.append("baseline_spike_detected")
                score += 5

            # ICMP Flood는 최종 ARP 시나리오의 보조 탐지 항목이다.
            # 여러 공격자 기반 DDoS로 부르지 않고, 단일 호스트의 과도한 ICMP로 보고 RATE_LIMIT만 제안한다.
            policy = self._policy(
                MitigationAction.RATE_LIMIT,
                {"ipv4_src": src_ip, "ipv4_dst": dst_ip, "ip_proto": "ICMP"},
                500,
                "icmp flood mitigation",
                rate_limit_pps=self.config.rate_limit_pps,
            )
            events.append(
                self._event(
                    "ICMP_FLOOD",
                    "High",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="ICMP",
                    metric_name="pps",
                    metric_value=round(pps, 3),
                    threshold=round(threshold, 3),
                    action=policy.action,
                    policy=policy,
                    evidence={
                        "matched_conditions": matched_conditions,
                        "packet_count": stats["packets"],
                        "baseline_pps": baseline,
                        "score": min(score, 100),
                        "response_level": "L2",
                        "recommended_action": "rate_limit",
                        "min_packet_count": min_required_packets,
                        "high_pps_threshold": round(high_pps_threshold, 3),
                        "window_seconds": self.config.window_seconds,
                    },
                    now=now,
                )
            )

        return events

    def _baseline_protocol_pps(self, src_ip: str, protocol: str) -> float:
        if self.baseline is None:
            return 0.0
        return self.baseline.protocol_pps_for_host(src_ip, protocol)

    def _policy(
        self,
        action: MitigationAction,
        match: dict[str, object],
        priority: int,
        reason: str,
        rate_limit_pps: int | None = None,
    ) -> MitigationPolicy:
        return MitigationPolicy(
            action=action,
            match=match,
            priority=priority,
            reason=reason,
            rate_limit_pps=rate_limit_pps,
            idle_timeout=self.config.mitigation_idle_timeout,
            hard_timeout=self.config.mitigation_hard_timeout,
        )

    def _event(
        self,
        attack_type: str,
        severity: str,
        *,
        src_ip: str = "",
        src_mac: str = "",
        dst_ip: str = "",
        dst_port: int | None = None,
        protocol: str = "",
        metric_name: str = "",
        metric_value: float | int | str | None = None,
        threshold: float | int | str | None = None,
        action: MitigationAction = MitigationAction.MONITOR_ONLY,
        policy: MitigationPolicy | None = None,
        evidence: dict[str, object] | None = None,
        now: datetime,
    ) -> SecurityEvent:
        event_evidence = evidence or {}
        return SecurityEvent(
            event_id=_event_id(
                attack_type,
                src_ip,
                src_mac,
                dst_ip,
                str(dst_port or ""),
                protocol,
                metric_name,
                str(event_evidence.get("spoofed_ip") or ""),
            ),
            attack_type=attack_type,
            severity=severity,
            src_ip=src_ip,
            src_mac=src_mac,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            metric_name=metric_name,
            metric_value=metric_value,
            threshold=threshold,
            status=EventStatus.DETECTED,
            action=action,
            evidence=event_evidence,
            policy=policy,
            created_at=now,
        )


def analyze_security_window(
    packets: Iterable[PacketRecord],
    links: Iterable[LinkState] | None = None,
    config: DetectionConfig | None = None,
    baseline: BaselineProfile | None = None,
) -> AnalysisResult:
    return SecurityAnalysisEngine(config=config, baseline=baseline).analyze(
        packets,
        links=links,
    )


def _group_packets(packets: list[PacketRecord], protocol: str) -> dict[tuple[str, str], dict[str, int]]:
    grouped: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for packet in packets:
        if packet.protocol_name != protocol or not packet.src_ip or not packet.dst_ip:
            continue
        key = (packet.src_ip, packet.dst_ip)
        grouped[key]["packets"] += max(packet.packet_count, 1)
        grouped[key]["bytes"] += max(packet.byte_count, 0)
    return grouped


def _analysis_time(packets: list[PacketRecord]) -> datetime:
    if packets:
        return max(packet.timestamp for packet in packets)
    return datetime.now(timezone.utc)


def _event_id(*parts: str) -> str:
    raw = "|".join(parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"evt-{digest}"
