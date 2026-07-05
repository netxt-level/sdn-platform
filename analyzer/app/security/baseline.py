from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .models import PacketRecord


@dataclass(frozen=True)
class BaselineProfile:
    window_seconds: float
    host_pps: dict[str, float] = field(default_factory=dict)
    host_bps: dict[str, float] = field(default_factory=dict)
    host_protocol_pps: dict[tuple[str, str], float] = field(default_factory=dict)
    protocol_ratio: dict[str, float] = field(default_factory=dict)
    path_usage: dict[str, int] = field(default_factory=dict)
    ip_mac: dict[str, str] = field(default_factory=dict)

    def pps_for_host(self, host: str) -> float:
        return self.host_pps.get(host, 0.0)

    def protocol_pps_for_host(self, host: str, protocol: str) -> float:
        return self.host_protocol_pps.get((host, protocol.upper()), 0.0)


def build_baseline(records: list[PacketRecord], window_seconds: float | None = None) -> BaselineProfile:
    duration = window_seconds or _window_seconds(records)
    host_packets: Counter[str] = Counter()
    host_bytes: Counter[str] = Counter()
    host_protocol_packets: Counter[tuple[str, str]] = Counter()
    protocol_packets: Counter[str] = Counter()
    path_usage: Counter[str] = Counter()
    ip_mac: dict[str, str] = {}

    for record in records:
        packets = max(record.packet_count, 1)
        host = record.src_ip or record.src_mac
        protocol = record.protocol_name
        if host:
            host_packets[host] += packets
            host_bytes[host] += max(record.byte_count, 0)
            host_protocol_packets[(host, protocol)] += packets
        if protocol:
            protocol_packets[protocol] += packets
        if record.path_id:
            path_usage[record.path_id] += packets
        if record.src_ip and record.src_mac:
            ip_mac.setdefault(record.src_ip, record.src_mac.lower())
        if record.arp_sender_ip and record.arp_sender_mac:
            ip_mac.setdefault(record.arp_sender_ip, record.arp_sender_mac.lower())

    total_packets = sum(protocol_packets.values()) or 1
    return BaselineProfile(
        window_seconds=duration,
        host_pps={host: count / duration for host, count in host_packets.items()},
        host_bps={host: count / duration for host, count in host_bytes.items()},
        host_protocol_pps={(host, proto): count / duration for (host, proto), count in host_protocol_packets.items()},
        protocol_ratio={proto: count / total_packets for proto, count in protocol_packets.items()},
        path_usage=dict(path_usage),
        ip_mac=ip_mac,
    )


def _window_seconds(records: list[PacketRecord]) -> float:
    if len(records) < 2:
        return 1.0
    timestamps = [record.timestamp for record in records]
    span = (max(timestamps) - min(timestamps)).total_seconds()
    return max(span, 1.0)
