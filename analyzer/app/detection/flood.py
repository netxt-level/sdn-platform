from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from .common import current_time, packet_time
from .common import clamp_score, score_policy, to_int, to_ip, to_port


@dataclass(frozen=True)
class FloodThresholds:
    """Flood 탐지에 필요한 기준값을 한 곳에 묶는다."""

    pps: float
    high_pps: float
    critical_pps: float
    minimum_packets: int
    bps: float = 0
    high_bps: float = 0
    critical_bps: float = 0
    history_size: int = 3
    required_exceeded_windows: int = 2
    retention_windows: int = 120


class FloodDetector:
    """
    단일 출발지와 목적지 사이의 PPS/BPS 증가를 기준으로 Flood를 탐지한다.

    UDP는 목적지 포트 단위 집계와 출발지-목적지 합산 집계를 함께 사용한다.
    그래서 특정 포트 공격은 좁게 대응하고, 여러 포트로 나눈 UDP Flood도 놓치지 않는다.
    여러 출발지가 한 목적지를 동시에 공격하는 분산 DDoS 집계는 별도 탐지기로 분리한다.
    """

    def __init__(
        self,
        *,
        protocol: str,
        attack_type: str,
        detection_rule: str,
        thresholds: FloodThresholds,
        icmp_type: int | None = None,
        group_by_dst_port: bool = False,
    ) -> None:
        self.protocol = protocol
        self.attack_type = attack_type
        self.detection_rule = detection_rule
        self.thresholds = thresholds
        self.icmp_type = icmp_type
        self.group_by_dst_port = group_by_dst_port
        self.history: dict[tuple[str, str, str, int | None], deque[bool]] = defaultdict(
            lambda: deque(maxlen=thresholds.history_size)
        )
        self.window_index = 0
        self.last_seen_window: dict[tuple[str, str, str, int | None], int] = {}
        self.last_seen_bucket: dict[tuple[str, str, str, int | None], int] = {}

    def detect(
        self,
        packets: list[dict[str, Any]],
        window_sec: int | float,
    ) -> list[dict[str, Any]]:
        fallback_time = current_time()
        use_packet_time_bucket = any(
            packet.get("timestamp") is not None
            for packet in packets
        )
        grouped_by_bucket = defaultdict(lambda: defaultdict(_new_flood_stats))
        pair_grouped_by_bucket = defaultdict(lambda: defaultdict(_new_flood_stats))

        for packet in packets:
            if packet.get("protocol") != self.protocol:
                continue
            if (
                self.icmp_type is not None
                and to_int(packet.get("icmp_type")) != self.icmp_type
            ):
                continue

            src_ip = to_ip(packet.get("src_ip"))
            dst_ip = to_ip(packet.get("dst_ip"))
            if not src_ip or not dst_ip:
                continue

            dst_port = to_port(packet.get("dst_port"))
            if self.group_by_dst_port and dst_port is None:
                continue

            packet_size = max(to_int(packet.get("packet_size")) or 0, 0)
            key = (src_ip, dst_ip, dst_port if self.group_by_dst_port else None)
            bucket_key = None
            if use_packet_time_bucket:
                bucket_key = int(packet_time(packet, fallback_time).timestamp())

            _add_flood_packet(
                grouped_by_bucket[bucket_key][key],
                packet_size,
                dst_port,
            )
            if self.group_by_dst_port:
                _add_flood_packet(
                    pair_grouped_by_bucket[bucket_key][(src_ip, dst_ip, None)],
                    packet_size,
                    dst_port,
                )

        alerts_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
        divisor = float(window_sec) if window_sec and window_sec > 0 else 1.0
        bucket_divisor = 1.0 if use_packet_time_bucket else divisor

        bucket_keys = _sorted_bucket_keys(grouped_by_bucket, pair_grouped_by_bucket)
        if not bucket_keys:
            self.window_index += 1
            self._cleanup_state()
            return []

        for bucket_start_epoch in bucket_keys:
            self.window_index += 1

            for (src_ip, dst_ip, dst_port), stats in grouped_by_bucket[
                bucket_start_epoch
            ].items():
                alert = self._build_alert(
                    scope="service",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    stats=stats,
                    divisor=bucket_divisor,
                    analysis_window_seconds=divisor,
                    bucket_start_epoch=bucket_start_epoch,
                )
                if alert is not None:
                    _remember_alert(alerts_by_key, alert)

            if not self.group_by_dst_port:
                continue

            for (src_ip, dst_ip, dst_port), stats in pair_grouped_by_bucket[
                bucket_start_epoch
            ].items():
                if len(stats["ports"]) <= 1:
                    continue
                alert = self._build_alert(
                    scope="pair",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    stats=stats,
                    divisor=bucket_divisor,
                    analysis_window_seconds=divisor,
                    bucket_start_epoch=bucket_start_epoch,
                )
                if alert is not None:
                    _remember_alert(alerts_by_key, alert)

        self._cleanup_state()
        return list(alerts_by_key.values())

    def _build_alert(
        self,
        *,
        scope: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None,
        stats: dict[str, Any],
        divisor: float,
        analysis_window_seconds: float,
        bucket_start_epoch: int | None,
    ) -> dict[str, Any] | None:
        packet_count = stats["packets"]
        pps = packet_count / divisor
        bps = (stats["bytes"] * 8) / divisor

        pps_exceeded = pps >= self.thresholds.pps
        bps_exceeded = self.thresholds.bps > 0 and bps >= self.thresholds.bps
        exceeded = pps_exceeded or bps_exceeded

        # 중간에 빈 구간이 있으면 연속 공격으로 이어 붙이지 않는다.
        key = (scope, src_ip, dst_ip, dst_port)
        history = self.history[key]
        last_seen_window = self.last_seen_window.get(key)
        last_seen_bucket = self.last_seen_bucket.get(key)
        if bucket_start_epoch is not None:
            if (
                last_seen_bucket is not None
                and bucket_start_epoch - last_seen_bucket > 1
            ):
                history.clear()
        elif (
            last_seen_window is not None
            and last_seen_window < self.window_index - 1
        ):
            history.clear()
        history.append(exceeded)
        self.last_seen_window[key] = self.window_index
        if bucket_start_epoch is not None:
            self.last_seen_bucket[key] = bucket_start_epoch
        else:
            self.last_seen_bucket.pop(key, None)
        exceeded_windows = sum(history)

        # Critical 급증도 첫 대응은 Rate Limit 후보로 두고, 지속될 때 Drop 후보로 올린다.
        immediate_critical = pps >= self.thresholds.critical_pps or (
            self.thresholds.critical_bps > 0
            and bps >= self.thresholds.critical_bps
        )
        sustained = (
            exceeded
            and packet_count >= self.thresholds.minimum_packets
            and exceeded_windows >= self.thresholds.required_exceeded_windows
        )
        if not immediate_critical and not sustained:
            return None

        conditions = [
            "ICMP Echo Request" if self.icmp_type == 8 else f"{self.protocol} 패킷"
        ]
        if scope == "pair":
            conditions.append("여러 목적지 포트 합산 기준 초과")
        score = 40

        if pps_exceeded:
            conditions.append("PPS 기준 초과")
            score += 15
        if bps_exceeded:
            conditions.append("BPS 기준 초과")
            score += 15
        if packet_count >= self.thresholds.minimum_packets:
            conditions.append("최소 패킷 수 기준 충족")
        if exceeded_windows >= self.thresholds.required_exceeded_windows:
            conditions.append("여러 분석 구간에서 반복 초과")
            score += 10
        if pps >= self.thresholds.high_pps or (
            self.thresholds.high_bps > 0 and bps >= self.thresholds.high_bps
        ):
            conditions.append("높은 트래픽 기준 초과")
            score += 15
        if immediate_critical:
            conditions.append("Critical 기준 즉시 초과")
            score = 90

        score = clamp_score(score)
        severity, response_level, recommended_action = score_policy(
            score,
            drop_allowed=sustained,
        )
        evidence = {
            "window_seconds": divisor,
            "packet_count": packet_count,
            "pps": pps,
            "bps": bps,
            "aggregation_scope": scope,
            "pps_threshold": self.thresholds.pps,
            "bps_threshold": self.thresholds.bps,
            "high_pps_threshold": self.thresholds.high_pps,
            "critical_pps_threshold": self.thresholds.critical_pps,
            "exceeded_windows": exceeded_windows,
            "required_exceeded_windows": (
                self.thresholds.required_exceeded_windows
            ),
            "drop_allowed": sustained,
            "mitigation_stage": "escalated" if sustained else "initial",
        }
        if bucket_start_epoch is not None:
            evidence["bucket_start_epoch"] = bucket_start_epoch
            evidence["analysis_window_seconds"] = analysis_window_seconds
        if immediate_critical and not sustained:
            evidence["escalation_reason"] = "critical rate observed once"
        elif sustained:
            evidence["escalation_reason"] = "repeated threshold exceeded"
        if self.icmp_type is not None:
            evidence["icmp_type"] = self.icmp_type

        ports = stats["ports"]
        if ports:
            evidence["unique_dst_port_count"] = len(ports)
            evidence["sample_dst_ports"] = sorted(ports)[:10]
            dominant_port, dominant_count = max(
                stats["port_counts"].items(),
                key=lambda item: item[1],
            )
            evidence["dominant_dst_port"] = dominant_port
            evidence["dominant_port_ratio"] = dominant_count / packet_count
        if dst_port is not None:
            evidence["destination_port"] = dst_port

        detection_rule = self.detection_rule
        if scope == "pair":
            detection_rule = f"{self.detection_rule}_pair_total"

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": self.protocol,
            "attack_category": "FLOOD",
            "attack_type": self.attack_type,
            "severity": severity,
            "confidence": "high" if immediate_critical or sustained else "medium",
            "detection_rule": detection_rule,
            "recommended_action": recommended_action,
            "response_level": response_level,
            "matched_conditions": conditions,
            "score": score,
            "evidence": evidence,
        }

    def _cleanup_state(self) -> None:
        stale_keys = [
            key
            for key, last_seen in self.last_seen_window.items()
            if self.window_index - last_seen > self.thresholds.retention_windows
        ]
        for key in stale_keys:
            self.history.pop(key, None)
            self.last_seen_window.pop(key, None)
            self.last_seen_bucket.pop(key, None)


def _new_flood_stats() -> dict[str, Any]:
    return {
        "packets": 0,
        "bytes": 0,
        "ports": set(),
        "port_counts": defaultdict(int),
    }


def _add_flood_packet(
    stats: dict[str, Any],
    packet_size: int,
    dst_port: int | None,
) -> None:
    stats["packets"] += 1
    stats["bytes"] += packet_size
    if dst_port is not None:
        stats["ports"].add(dst_port)
        stats["port_counts"][dst_port] += 1


def _sorted_bucket_keys(*grouped_maps) -> list[int | None]:
    keys = set()
    for grouped_map in grouped_maps:
        keys.update(grouped_map.keys())
    return sorted(keys, key=lambda value: -1 if value is None else value)


def _remember_alert(
    alerts_by_key: dict[tuple[Any, ...], dict[str, Any]],
    alert: dict[str, Any],
) -> None:
    key = (
        alert["detection_rule"],
        alert["src_ip"],
        alert["dst_ip"],
        alert["evidence"].get("destination_port"),
        alert["evidence"].get("aggregation_scope"),
    )
    current = alerts_by_key.get(key)
    if current is None or _alert_rank(alert) >= _alert_rank(current):
        alerts_by_key[key] = alert


def _alert_rank(alert: dict[str, Any]) -> tuple[int, int, int]:
    evidence = alert.get("evidence") or {}
    return (
        int(alert.get("score") or 0),
        int(evidence.get("exceeded_windows") or 0),
        int(evidence.get("bucket_start_epoch") or 0),
    )


class IcmpFloodDetector(FloodDetector):
    """ICMP Flood 전용 탐지기."""

    def __init__(self, thresholds: FloodThresholds) -> None:
        super().__init__(
            protocol="ICMP",
            attack_type="ICMP_FLOOD",
            detection_rule="icmp_flood_rate_threshold",
            thresholds=thresholds,
            icmp_type=8,
        )


class UdpFloodDetector(FloodDetector):
    """UDP Flood 전용 탐지기."""

    def __init__(self, thresholds: FloodThresholds) -> None:
        super().__init__(
            protocol="UDP",
            attack_type="UDP_FLOOD",
            detection_rule="udp_flood_rate_threshold",
            thresholds=thresholds,
            group_by_dst_port=True,
        )
