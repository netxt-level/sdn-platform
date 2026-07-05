from __future__ import annotations

from datetime import datetime, timezone
from numbers import Real
from typing import Any

from .models import LinkState, MitigationAction, MitigationPolicy, PacketRecord


IP_PROTO_NUMBERS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
}

ETH_TYPES = {
    "IPv4": 0x0800,
    "IPV4": 0x0800,
    "ARP": 0x0806,
}


def packet_record_from_ryu(raw: dict[str, Any]) -> PacketRecord:
    """Convert controller packet metadata to the neutral security model.

    This function intentionally accepts plain dictionaries so the security
    package can be used from Ryu apps without importing Ryu in tests.
    """

    protocol = _protocol_name(raw.get("protocol") or raw.get("ip_proto") or raw.get("nw_proto"))
    if not protocol:
        protocol = _protocol_from_eth_type(raw.get("eth_type") or raw.get("dl_type"))
    return PacketRecord(
        timestamp=_parse_datetime(raw.get("timestamp")),
        src_ip=str(raw.get("src_ip") or raw.get("ipv4_src") or raw.get("arp_spa") or ""),
        dst_ip=str(raw.get("dst_ip") or raw.get("ipv4_dst") or raw.get("arp_tpa") or ""),
        protocol=protocol,
        src_mac=str(raw.get("src_mac") or raw.get("eth_src") or raw.get("arp_sha") or ""),
        dst_mac=str(raw.get("dst_mac") or raw.get("eth_dst") or raw.get("arp_tha") or ""),
        src_port=_optional_int(raw.get("src_port") or raw.get("tcp_src") or raw.get("udp_src")),
        dst_port=_optional_int(raw.get("dst_port") or raw.get("tcp_dst") or raw.get("udp_dst")),
        tcp_flags=_tcp_flags(raw.get("tcp_flags")),
        packet_count=int(raw.get("packet_count") or 1),
        byte_count=int(raw.get("byte_count") or raw.get("bytes") or raw.get("packet_size") or 0),
        switch_id=str(raw.get("switch_id") or raw.get("dpid") or raw.get("datapath_id") or ""),
        in_port=_optional_int(raw.get("in_port")),
        out_port=_optional_int(raw.get("out_port")),
        path_id=str(raw.get("path_id") or ""),
        arp_opcode=str(raw.get("arp_opcode") or raw.get("opcode") or ""),
        arp_sender_ip=str(raw.get("arp_sender_ip") or raw.get("arp_spa") or ""),
        arp_sender_mac=str(raw.get("arp_sender_mac") or raw.get("arp_sha") or ""),
        arp_target_ip=str(raw.get("arp_target_ip") or raw.get("arp_tpa") or ""),
        arp_target_mac=str(raw.get("arp_target_mac") or raw.get("arp_tha") or ""),
    )


def link_state_from_port_stats(
    raw: dict[str, Any],
    *,
    interval_seconds: float,
    capacity_bps: float,
) -> LinkState:
    """Convert a port/link stats sample to a LinkState.

    Expected byte fields are deltas over the sampling interval. If the caller
    only has absolute counters, compute deltas before calling this function.
    """

    tx_delta = int(raw.get("tx_bytes_delta") or raw.get("byte_delta") or 0)
    rx_delta = int(raw.get("rx_bytes_delta") or 0)
    total_bps = ((tx_delta + rx_delta) * 8) / max(interval_seconds, 1.0)
    utilization = min(total_bps / capacity_bps, 1.0) if capacity_bps > 0 else 0.0
    link_id = str(raw.get("link_id") or _link_id(raw))
    return LinkState(
        link_id=link_id,
        src_switch=str(raw.get("src_switch") or raw.get("switch_id") or raw.get("dpid") or ""),
        src_port=_optional_int(raw.get("src_port") or raw.get("port_no")),
        dst_switch=str(raw.get("dst_switch") or ""),
        dst_port=_optional_int(raw.get("dst_port")),
        utilization=utilization,
        latency_ms=_optional_float(raw.get("latency_ms")),
        queue_len=_optional_int(raw.get("queue_len")),
        packet_drop_delta=int(raw.get("packet_drop_delta") or raw.get("tx_dropped_delta") or raw.get("rx_dropped_delta") or 0),
        status=str(raw.get("status") or "up"),
    )


def flow_rule_from_policy(policy: MitigationPolicy, *, datapath_id: str | None = None) -> dict[str, Any]:
    """Create a Ryu-friendly FlowMod description from a mitigation policy.

    The returned dictionary is deliberately serializable. The controller owner
    can map it to parser.OFPMatch, parser.OFPActionOutput, meters, and FlowMod.
    """

    match = _normalize_match(policy.match)
    base = {
        "datapath_id": datapath_id,
        "priority": policy.priority,
        "match": match,
        "idle_timeout": policy.idle_timeout,
        "hard_timeout": policy.hard_timeout,
        "reason": policy.reason,
    }
    if policy.action == MitigationAction.DROP:
        return {**base, "actions": [], "instruction": "DROP"}
    if policy.action == MitigationAction.RATE_LIMIT:
        return {
            **base,
            "actions": [{"type": "METER", "rate_limit_pps": policy.rate_limit_pps}],
            "instruction": "RATE_LIMIT",
        }
    if policy.action == MitigationAction.REROUTE:
        return {
            **base,
            "actions": [{"type": "REROUTE", "path": policy.reroute_path or "bypass"}],
            "instruction": "REROUTE",
        }
    return {
        **base,
        "actions": [{"type": "CONTROLLER"}],
        "instruction": "MONITOR_ONLY",
    }


def flow_rules_from_policies(policies: list[MitigationPolicy], *, datapath_id: str | None = None) -> list[dict[str, Any]]:
    return [flow_rule_from_policy(policy, datapath_id=datapath_id) for policy in policies]


def _normalize_match(match: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in match.items():
        if key == "ip_proto" and isinstance(value, str):
            normalized["eth_type"] = ETH_TYPES["IPv4"]
            normalized[key] = IP_PROTO_NUMBERS.get(value.upper(), value)
        elif key == "eth_type" and isinstance(value, str):
            normalized[key] = ETH_TYPES.get(value.upper(), value)
        else:
            normalized[key] = value
    return normalized


def _protocol_name(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, int):
        return {number: name for name, number in IP_PROTO_NUMBERS.items()}.get(value, str(value))
    text = str(value).upper()
    if text in {"1", "6", "17"}:
        return _protocol_name(int(text))
    return text


def _protocol_from_eth_type(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        text = value.upper()
        if text.startswith("0X"):
            number = int(text, 16)
        elif text in ETH_TYPES:
            return text
        else:
            number = int(text)
    else:
        number = int(value)
    if number == ETH_TYPES["ARP"]:
        return "ARP"
    if number == ETH_TYPES["IPv4"]:
        return "IPv4"
    return ""


def _tcp_flags(value: Any) -> tuple[str, ...]:
    if value is None or value == "":
        return ()
    if isinstance(value, str):
        raw_flags = [part.strip().upper() for part in value.replace("|", ",").split(",") if part.strip()]
    if isinstance(value, (list, tuple, set)):
        raw_flags = [str(part).upper() for part in value]
    if not isinstance(value, (str, list, tuple, set)):
        raw_flags = [str(value).upper()]
    aliases = {
        "S": "SYN",
        "SA": "SYN,ACK",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
    }
    normalized: list[str] = []
    for flag in raw_flags:
        expanded = aliases.get(flag, flag)
        normalized.extend(part for part in expanded.split(",") if part)
    return tuple(normalized)


def _link_id(raw: dict[str, Any]) -> str:
    src_switch = raw.get("src_switch") or raw.get("switch_id") or raw.get("dpid") or "unknown"
    src_port = raw.get("src_port") or raw.get("port_no") or "unknown"
    dst_switch = raw.get("dst_switch") or "unknown"
    dst_port = raw.get("dst_port") or "unknown"
    return f"{src_switch}:{src_port}-{dst_switch}:{dst_port}"


def _parse_datetime(value: Any) -> datetime:
    if value in (None, ""):
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, Real):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def _optional_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    return float(value)
