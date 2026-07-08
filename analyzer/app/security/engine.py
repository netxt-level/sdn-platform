from __future__ import annotations

from collections import Counter, defaultdict
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
        link_list = list(links or [])
        events: list[SecurityEvent] = []

        events.extend(self._detect_port_scan(window_packets, now))
        events.extend(self._detect_icmp_flood(window_packets, now))
        events.extend(self._detect_udp_flood(window_packets, now))
        events.extend(self._detect_syn_flood(window_packets, now))
        events.extend(self._detect_arp_spoofing(window_packets, now))
        events.extend(self._detect_congestion(link_list, now))
        events.extend(self._detect_link_failure(link_list, now))

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

    def _detect_port_scan(self, packets: list[PacketRecord], now: datetime) -> list[SecurityEvent]:
        # 같은 출발지/목적지 사이에서 접근한 목적지 포트 수를 센다.
        # 짧은 시간 안에 여러 포트를 훑으면 정찰 행위로 보고 PORT_SCAN 이벤트를 만든다.
        ports_by_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
        protocol_by_pair: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        for packet in packets:
            if packet.protocol_name not in {"TCP", "UDP"} or packet.dst_port is None:
                continue
            if not packet.src_ip or not packet.dst_ip:
                continue
            key = (packet.src_ip, packet.dst_ip)
            ports_by_pair[key].add(packet.dst_port)
            protocol_by_pair[key][packet.protocol_name] += max(packet.packet_count, 1)

        events: list[SecurityEvent] = []
        for (src_ip, dst_ip), ports in ports_by_pair.items():
            port_count = len(ports)
            if port_count < self.config.port_scan_unique_ports:
                continue

            # Port Scan은 바로 DROP하지 않고 rate limit 후보 정책으로 만든다.
            # 정상 진단 트래픽과 헷갈릴 수 있어서 차단보다 완화 정책에 가깝게 둔다.
            protocols = sorted(protocol_by_pair[(src_ip, dst_ip)].keys())
            protocol = protocols[0] if len(protocols) == 1 else "MIXED"
            match = {"ipv4_src": src_ip, "ipv4_dst": dst_ip}
            if len(protocols) == 1:
                match["ip_proto"] = protocol
            policy = self._policy(
                MitigationAction.RATE_LIMIT,
                match,
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
                    protocol=protocol,
                    metric_name="unique_dst_ports",
                    metric_value=port_count,
                    threshold=self.config.port_scan_unique_ports,
                    action=policy.action,
                    policy=policy,
                    evidence={"ports": sorted(ports)[:50], "protocols": protocols, "window_seconds": self.config.window_seconds},
                    now=now,
                )
            )
        return events

    def _detect_icmp_flood(self, packets: list[PacketRecord], now: datetime) -> list[SecurityEvent]:
        # ICMP 패킷을 출발지/목적지 단위로 묶어 PPS를 계산한다.
        # 기준값 또는 baseline 대비 급증 기준을 넘으면 ICMP_FLOOD로 판단한다.
        grouped = _group_packets(packets, protocol="ICMP")
        events: list[SecurityEvent] = []
        for (src_ip, dst_ip), stats in grouped.items():
            pps = stats["packets"] / self.config.window_seconds
            baseline = self._baseline_protocol_pps(src_ip, "ICMP")
            threshold = max(self.config.icmp_pps_threshold, baseline * self.config.baseline_multiplier)
            if pps < threshold:
                continue

            # ICMP Flood는 서비스 가용성에 영향을 주므로 rate limit 정책을 함께 만든다.
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
                    evidence={"packet_count": stats["packets"], "baseline_pps": baseline},
                    now=now,
                )
            )
        return events

    def _detect_udp_flood(self, packets: list[PacketRecord], now: datetime) -> list[SecurityEvent]:
        grouped = _group_packets(packets, protocol="UDP")
        events: list[SecurityEvent] = []
        for (src_ip, dst_ip), stats in grouped.items():
            pps = stats["packets"] / self.config.window_seconds
            bps = stats["bytes"] / self.config.window_seconds
            baseline_pps = self._baseline_protocol_pps(src_ip, "UDP")
            threshold_pps = max(self.config.udp_pps_threshold, baseline_pps * self.config.baseline_multiplier)
            exceeds_pps = pps >= threshold_pps
            exceeds_bps = bps >= self.config.udp_bps_threshold
            if not (exceeds_pps or exceeds_bps):
                continue
            metric_name = "pps" if exceeds_pps else "bps"
            metric_value = pps if exceeds_pps else bps
            threshold = threshold_pps if exceeds_pps else self.config.udp_bps_threshold
            policy = self._policy(
                MitigationAction.RATE_LIMIT,
                {"ipv4_src": src_ip, "ipv4_dst": dst_ip, "ip_proto": "UDP"},
                500,
                "udp flood mitigation",
                rate_limit_pps=self.config.rate_limit_pps,
            )
            events.append(
                self._event(
                    "UDP_FLOOD",
                    "High",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="UDP",
                    metric_name=metric_name,
                    metric_value=round(metric_value, 3),
                    threshold=round(threshold, 3),
                    action=policy.action,
                    policy=policy,
                    evidence={"packet_count": stats["packets"], "byte_count": stats["bytes"], "baseline_pps": baseline_pps},
                    now=now,
                )
            )
        return events

    def _detect_syn_flood(self, packets: list[PacketRecord], now: datetime) -> list[SecurityEvent]:
        tcp_totals: Counter[tuple[str, str, int | None]] = Counter()
        syn_totals: Counter[tuple[str, str, int | None]] = Counter()
        for packet in packets:
            if packet.protocol_name != "TCP" or not packet.src_ip or not packet.dst_ip:
                continue
            key = (packet.src_ip, packet.dst_ip, packet.dst_port)
            tcp_totals[key] += max(packet.packet_count, 1)
            if packet.is_syn_only:
                syn_totals[key] += max(packet.packet_count, 1)

        events: list[SecurityEvent] = []
        for key, syn_count in syn_totals.items():
            src_ip, dst_ip, dst_port = key
            total = tcp_totals[key]
            syn_pps = syn_count / self.config.window_seconds
            syn_ratio = syn_count / total if total else 0.0
            baseline = self._baseline_protocol_pps(src_ip, "TCP")
            threshold_pps = max(self.config.syn_pps_threshold, baseline * self.config.baseline_multiplier)
            enough_samples = syn_count >= self.config.min_sample_packets
            if not enough_samples or (syn_pps < threshold_pps and syn_ratio < self.config.syn_ratio_threshold):
                continue
            policy = self._policy(
                MitigationAction.RATE_LIMIT,
                {"ipv4_src": src_ip, "ipv4_dst": dst_ip, "ip_proto": "TCP", "tcp_flags": "SYN"},
                550,
                "syn flood mitigation",
                rate_limit_pps=self.config.rate_limit_pps,
            )
            events.append(
                self._event(
                    "SYN_FLOOD",
                    "High",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol="TCP",
                    metric_name="syn_ratio",
                    metric_value=round(syn_ratio, 3),
                    threshold=self.config.syn_ratio_threshold,
                    action=policy.action,
                    policy=policy,
                    evidence={"syn_count": syn_count, "tcp_count": total, "syn_pps": round(syn_pps, 3), "threshold_pps": threshold_pps},
                    now=now,
                )
            )
        return events

    def _detect_arp_spoofing(self, packets: list[PacketRecord], now: datetime) -> list[SecurityEvent]:
        trusted = {ip: mac.lower() for ip, mac in self.config.trusted_ip_mac.items()}
        if self.config.gateway_ip and self.config.gateway_mac:
            trusted[self.config.gateway_ip] = self.config.gateway_mac.lower()
        if self.baseline:
            trusted = {**self.baseline.ip_mac, **trusted}

        observed: dict[str, set[str]] = defaultdict(set)
        arp_context: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"target_ips": set(), "target_macs": set(), "opcodes": set()})
        reply_counter: Counter[tuple[str, str]] = Counter()
        for packet in packets:
            if packet.protocol_name != "ARP":
                continue
            sender_ip = packet.arp_sender_ip or packet.src_ip
            sender_mac = (packet.arp_sender_mac or packet.src_mac).lower()
            if not sender_ip or not sender_mac:
                continue
            observed[sender_ip].add(sender_mac)
            if packet.arp_target_ip:
                arp_context[sender_ip]["target_ips"].add(packet.arp_target_ip)
            if packet.arp_target_mac:
                arp_context[sender_ip]["target_macs"].add(packet.arp_target_mac.lower())
            if packet.arp_opcode:
                arp_context[sender_ip]["opcodes"].add(packet.arp_opcode.lower())
            if packet.is_arp_reply:
                reply_counter[(sender_ip, sender_mac)] += max(packet.packet_count, 1)

        events: list[SecurityEvent] = []
        for ip, macs in observed.items():
            trusted_mac = trusted.get(ip)
            duplicate_mapping = len(macs) >= 2
            gateway_changed = bool(trusted_mac and any(mac != trusted_mac for mac in macs))
            if not duplicate_mapping and not gateway_changed:
                continue
            attacker_mac = next((mac for mac in sorted(macs) if mac != trusted_mac), sorted(macs)[0])
            reason = "trusted_mac_mismatch" if gateway_changed else "duplicate_ip_mac_mapping"
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

        for (sender_ip, sender_mac), count in reply_counter.items():
            pps = count / self.config.window_seconds
            if pps < self.config.arp_reply_pps_threshold:
                continue
            policy = self._policy(
                MitigationAction.RATE_LIMIT,
                {"eth_type": "ARP", "arp_spa": sender_ip, "eth_src": sender_mac},
                600,
                "arp reply storm mitigation",
                rate_limit_pps=self.config.rate_limit_pps,
            )
            events.append(
                self._event(
                    "ARP_REPLY_STORM",
                    "Medium",
                    src_mac=sender_mac,
                    protocol="ARP",
                    metric_name="pps",
                    metric_value=round(pps, 3),
                    threshold=self.config.arp_reply_pps_threshold,
                    action=policy.action,
                    policy=policy,
                    evidence={"sender_ip": sender_ip, "reply_count": count},
                    now=now,
                )
            )
        return events

    def _detect_congestion(self, links: list[LinkState], now: datetime) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        for link in links:
            latency_hit = link.latency_ms is not None and link.latency_ms >= self.config.congestion_latency_ms_threshold
            queue_hit = link.queue_len is not None and link.queue_len >= self.config.congestion_queue_threshold
            drop_hit = link.packet_drop_delta > 0
            utilization_hit = link.utilization >= self.config.congestion_utilization_threshold
            if link.is_down or not (utilization_hit or latency_hit or queue_hit or drop_hit):
                continue
            policy = self._policy(
                MitigationAction.REROUTE,
                {"avoid_link": link.link_id},
                300,
                "congested link reroute",
                reroute_path="bypass",
            )
            events.append(
                self._event(
                    "CONGESTION",
                    "Medium",
                    metric_name="link_utilization",
                    metric_value=round(link.utilization, 3),
                    threshold=self.config.congestion_utilization_threshold,
                    action=policy.action,
                    policy=policy,
                    evidence={
                        "link_id": link.link_id,
                        "latency_ms": link.latency_ms,
                        "queue_len": link.queue_len,
                        "packet_drop_delta": link.packet_drop_delta,
                    },
                    now=now,
                )
            )
        return events

    def _detect_link_failure(self, links: list[LinkState], now: datetime) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        for link in links:
            if not link.is_down:
                continue
            policy = self._policy(
                MitigationAction.REROUTE,
                {"avoid_link": link.link_id},
                700,
                "failed link bypass",
                reroute_path="bypass",
            )
            events.append(
                self._event(
                    "LINK_FAILURE",
                    "High",
                    metric_name="link_status",
                    metric_value=link.status,
                    threshold="up",
                    action=policy.action,
                    policy=policy,
                    evidence={"link_id": link.link_id, "src_switch": link.src_switch, "dst_switch": link.dst_switch},
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
        reroute_path: str | None = None,
    ) -> MitigationPolicy:
        return MitigationPolicy(
            action=action,
            match=match,
            priority=priority,
            reason=reason,
            rate_limit_pps=rate_limit_pps,
            idle_timeout=self.config.mitigation_idle_timeout,
            hard_timeout=self.config.mitigation_hard_timeout,
            reroute_path=reroute_path,
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
                str(event_evidence.get("link_id") or ""),
                str(event_evidence.get("ip") or event_evidence.get("spoofed_ip") or ""),
                str(event_evidence.get("sender_ip") or ""),
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
    return SecurityAnalysisEngine(config=config, baseline=baseline).analyze(packets, links=links)


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
