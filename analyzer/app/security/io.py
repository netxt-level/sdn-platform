from __future__ import annotations

from datetime import datetime, timezone
import csv
import json
from pathlib import Path
from typing import Any

from .baseline import BaselineProfile, build_baseline
from .models import AnalysisResult, DetectionConfig, LinkState, PacketRecord


def load_security_input(path: str | Path) -> tuple[list[PacketRecord], list[LinkState], BaselineProfile | None, DetectionConfig]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    config = _config_from_dict(payload.get("config", {}))
    packets = [packet_from_dict(item) for item in payload.get("packets", [])]
    links = [link_from_dict(item) for item in payload.get("links", [])]
    baseline = None
    if payload.get("baseline_packets"):
        baseline = build_baseline([packet_from_dict(item) for item in payload["baseline_packets"]], config.window_seconds)
    return packets, links, baseline, config


def packet_from_dict(raw: dict[str, Any]) -> PacketRecord:
    return PacketRecord(
        timestamp=_parse_datetime(raw.get("timestamp")),
        src_ip=str(raw.get("src_ip") or ""),
        dst_ip=str(raw.get("dst_ip") or ""),
        protocol=str(raw.get("protocol") or "").upper(),
        src_mac=str(raw.get("src_mac") or ""),
        dst_mac=str(raw.get("dst_mac") or ""),
        src_port=_optional_int(raw.get("src_port")),
        dst_port=_optional_int(raw.get("dst_port")),
        tcp_flags=_tcp_flags(raw.get("tcp_flags")),
        packet_count=int(raw.get("packet_count") or 1),
        byte_count=int(raw.get("byte_count") or 0),
        switch_id=str(raw.get("switch_id") or ""),
        in_port=_optional_int(raw.get("in_port")),
        out_port=_optional_int(raw.get("out_port")),
        path_id=str(raw.get("path_id") or ""),
        arp_opcode=str(raw.get("arp_opcode") or ""),
        arp_sender_ip=str(raw.get("arp_sender_ip") or ""),
        arp_sender_mac=str(raw.get("arp_sender_mac") or ""),
        arp_target_ip=str(raw.get("arp_target_ip") or ""),
        arp_target_mac=str(raw.get("arp_target_mac") or ""),
    )


def link_from_dict(raw: dict[str, Any]) -> LinkState:
    return LinkState(
        link_id=str(raw.get("link_id") or ""),
        src_switch=str(raw.get("src_switch") or ""),
        src_port=_optional_int(raw.get("src_port")),
        dst_switch=str(raw.get("dst_switch") or ""),
        dst_port=_optional_int(raw.get("dst_port")),
        utilization=float(raw.get("utilization") or 0.0),
        latency_ms=_optional_float(raw.get("latency_ms")),
        queue_len=_optional_int(raw.get("queue_len")),
        packet_drop_delta=int(raw.get("packet_drop_delta") or 0),
        status=str(raw.get("status") or "up"),
    )


def write_events_json(path: str | Path, result: AnalysisResult) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")


def write_events_csv(path: str | Path, result: AnalysisResult) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "event_id",
        "attack_type",
        "severity",
        "src_ip",
        "src_mac",
        "dst_ip",
        "dst_port",
        "protocol",
        "metric_name",
        "metric_value",
        "threshold",
        "status",
        "action",
        "created_at",
    ]
    with output.open("w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        for event in result.events:
            row = event.to_dict()
            writer.writerow({field: row.get(field, "") for field in fields})


def render_security_report(result: AnalysisResult) -> str:
    lines = [
        "# SDN Security Analysis Report",
        "",
        "## Summary",
        "",
        f"- Window seconds: {result.window_seconds:g}",
        f"- Packet count: {result.packet_count}",
        f"- Event count: {len(result.events)}",
        "",
        "## Events",
        "",
    ]
    if not result.events:
        lines.append("- No security event detected.")
    else:
        lines.extend(
            [
                "| Severity | Type | Source | Destination | Metric | Action |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for event in result.events:
            dst = f"{event.dst_ip}:{event.dst_port}" if event.dst_port else event.dst_ip
            metric = f"{event.metric_name}={event.metric_value} / threshold={event.threshold}"
            lines.append(
                f"| {event.severity} | {event.attack_type} | {event.src_ip or event.src_mac or '-'} | "
                f"{dst or '-'} | {metric} | {event.action.value} |"
            )

    lines.extend(["", "## Controller Policy Output", ""])
    if not result.policies:
        lines.append("- No controller policy required.")
    else:
        for index, policy in enumerate(result.policies, 1):
            lines.append(f"{index}. `{policy.action.value}` priority `{policy.priority}` match `{policy.match}`")
    return "\n".join(lines) + "\n"


def write_security_report(path: str | Path, result: AnalysisResult) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_security_report(result), encoding="utf-8")


def _config_from_dict(raw: dict[str, Any]) -> DetectionConfig:
    allowed = DetectionConfig.__dataclass_fields__.keys()
    return DetectionConfig(**{key: value for key, value in raw.items() if key in allowed})


def _parse_datetime(value: Any) -> datetime:
    if value in (None, ""):
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return value
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def _optional_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    return float(value)


def _tcp_flags(value: Any) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if isinstance(value, str):
        raw_flags = [part.strip().upper() for part in value.replace("|", ",").split(",") if part.strip()]
    elif isinstance(value, (list, tuple, set)):
        raw_flags = [str(part).upper() for part in value]
    else:
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
