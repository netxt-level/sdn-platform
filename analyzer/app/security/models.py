from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class EventStatus(StrEnum):
    DETECTED = "Detected"
    MITIGATING = "Mitigating"
    MITIGATED = "Mitigated"
    RESOLVED = "Resolved"


class MitigationAction(StrEnum):
    DROP = "DROP"
    RATE_LIMIT = "RATE_LIMIT"
    REROUTE = "REROUTE"
    MONITOR_ONLY = "MONITOR_ONLY"


@dataclass(frozen=True)
class PacketRecord:
    timestamp: datetime
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: tuple[str, ...] = ()
    packet_count: int = 1
    byte_count: int = 0
    switch_id: str = ""
    in_port: int | None = None
    out_port: int | None = None
    path_id: str = ""
    arp_opcode: str = ""
    arp_sender_ip: str = ""
    arp_sender_mac: str = ""
    arp_target_ip: str = ""
    arp_target_mac: str = ""

    @property
    def protocol_name(self) -> str:
        return self.protocol.upper()

    @property
    def is_syn_only(self) -> bool:
        flags = {flag.upper() for flag in self.tcp_flags}
        return "SYN" in flags and "ACK" not in flags

    @property
    def is_arp_reply(self) -> bool:
        return self.protocol_name == "ARP" and self.arp_opcode.lower() in {"reply", "2"}


@dataclass(frozen=True)
class LinkState:
    link_id: str
    src_switch: str = ""
    src_port: int | None = None
    dst_switch: str = ""
    dst_port: int | None = None
    utilization: float = 0.0
    latency_ms: float | None = None
    queue_len: int | None = None
    packet_drop_delta: int = 0
    status: str = "up"

    @property
    def is_down(self) -> bool:
        return self.status.lower() in {"down", "failed", "failure", "disabled"}


@dataclass(frozen=True)
class DetectionConfig:
    window_seconds: float = 10.0
    baseline_multiplier: float = 5.0
    min_sample_packets: int = 3
    icmp_pps_threshold: float = 100.0
    port_scan_unique_ports: int = 20
    rate_limit_pps: int = 50
    mitigation_idle_timeout: int = 60
    mitigation_hard_timeout: int = 300
    trusted_ip_mac: dict[str, str] = field(default_factory=dict)
    gateway_ip: str = ""
    gateway_mac: str = ""


@dataclass(frozen=True)
class MitigationPolicy:
    action: MitigationAction
    match: dict[str, Any]
    priority: int
    reason: str
    rate_limit_pps: int | None = None
    idle_timeout: int = 60
    hard_timeout: int = 300
    reroute_path: str | None = None

    def to_flow_rule(self) -> dict[str, Any]:
        instruction: dict[str, Any] = {
            "action": self.action.value,
            "match": self.match,
            "priority": self.priority,
            "idle_timeout": self.idle_timeout,
            "hard_timeout": self.hard_timeout,
            "reason": self.reason,
        }
        if self.rate_limit_pps is not None:
            instruction["rate_limit_pps"] = self.rate_limit_pps
        if self.reroute_path is not None:
            instruction["reroute_path"] = self.reroute_path
        return instruction


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    attack_type: str
    severity: str
    src_ip: str = ""
    src_mac: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    protocol: str = ""
    metric_name: str = ""
    metric_value: float | int | str | None = None
    threshold: float | int | str | None = None
    status: EventStatus = EventStatus.DETECTED
    action: MitigationAction = MitigationAction.MONITOR_ONLY
    evidence: dict[str, Any] = field(default_factory=dict)
    policy: MitigationPolicy | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "src_mac": self.src_mac,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "threshold": self.threshold,
            "status": self.status.value,
            "action": self.action.value,
            "evidence": self.evidence,
            "flow_rule": self.policy.to_flow_rule() if self.policy else None,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class AnalysisResult:
    window_seconds: float
    packet_count: int
    events: list[SecurityEvent] = field(default_factory=list)
    policies: list[MitigationPolicy] = field(default_factory=list)

    @property
    def has_events(self) -> bool:
        return bool(self.events)

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_seconds": self.window_seconds,
            "packet_count": self.packet_count,
            "event_count": len(self.events),
            "events": [event.to_dict() for event in self.events],
            "policies": [policy.to_flow_rule() for policy in self.policies],
        }
