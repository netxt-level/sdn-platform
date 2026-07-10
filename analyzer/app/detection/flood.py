from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from .common import clamp_score, score_policy, to_int, to_port


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
    """특정 프로토콜의 과도한 패킷 또는 트래픽 증가를 탐지한다."""

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
        self.history: dict[tuple[str, str, int | None], deque[bool]] = defaultdict(
            lambda: deque(maxlen=thresholds.history_size)
        )
        self.window_index = 0
        self.last_seen_window: dict[tuple[str, str, int | None], int] = {}

    def detect(
        self,
        packets: list[dict[str, Any]],
        window_sec: int | float,
    ) -> list[dict[str, Any]]:
        self.window_index += 1
        grouped = defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set()})

        for packet in packets:
            if packet.get("protocol") != self.protocol:
                continue
            if self.icmp_type is not None and to_int(packet.get("icmp_type")) != self.icmp_type:
                continue

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            if not src_ip or not dst_ip:
                continue

            dst_port = to_port(packet.get("dst_port"))
            if self.group_by_dst_port and dst_port is None:
                continue

            key = (str(src_ip), str(dst_ip), dst_port if self.group_by_dst_port else None)
            grouped[key]["packets"] += 1
            packet_size = max(to_int(packet.get("packet_size")) or 0, 0)
            grouped[key]["bytes"] += packet_size
            if dst_port is not None:
                grouped[key]["ports"].add(dst_port)

        alerts = []
        divisor = float(window_sec) if window_sec and window_sec > 0 else 1.0

        for (src_ip, dst_ip, dst_port), stats in grouped.items():
            packet_count = stats["packets"]
            pps = packet_count / divisor
            bps = (stats["bytes"] * 8) / divisor

            pps_exceeded = pps >= self.thresholds.pps
            bps_exceeded = self.thresholds.bps > 0 and bps >= self.thresholds.bps
            exceeded = pps_exceeded or bps_exceeded

            # 중간에 관측되지 않은 구간이 있으면 연속 공격으로 보지 않고 기록을 새로 시작한다.
            key = (src_ip, dst_ip, dst_port)
            history = self.history[key]
            last_seen = self.last_seen_window.get(key)
            if last_seen is not None and last_seen < self.window_index - 1:
                history.clear()
            history.append(exceeded)
            self.last_seen_window[key] = self.window_index
            exceeded_windows = sum(history)

            # Critical 급증은 즉시 보고하되, 첫 대응은 Rate Limit 후보로 제한한다.
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
                continue

            conditions = [
                "ICMP Echo Request" if self.icmp_type == 8 else f"{self.protocol} 패킷"
            ]
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
                "pps_threshold": self.thresholds.pps,
                "bps_threshold": self.thresholds.bps,
                "high_pps_threshold": self.thresholds.high_pps,
                "critical_pps_threshold": self.thresholds.critical_pps,
                "exceeded_windows": exceeded_windows,
                "required_exceeded_windows": (
                    self.thresholds.required_exceeded_windows
                ),
                "drop_allowed": sustained,
            }
            if self.icmp_type is not None:
                evidence["icmp_type"] = self.icmp_type
            if stats["ports"]:
                evidence["unique_dst_port_count"] = len(stats["ports"])
            if dst_port is not None:
                evidence["destination_port"] = dst_port
                evidence["dominant_dst_port"] = dst_port
                evidence["dominant_port_ratio"] = 1.0

            alerts.append(
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": self.protocol,
                    "attack_category": "FLOOD",
                    "attack_type": self.attack_type,
                    "severity": severity,
                    "confidence": (
                        "high" if immediate_critical or sustained else "medium"
                    ),
                    "detection_rule": self.detection_rule,
                    "recommended_action": recommended_action,
                    "response_level": response_level,
                    "matched_conditions": conditions,
                    "score": score,
                    "evidence": evidence,
                }
            )

        self._cleanup_state()
        return alerts

    def _cleanup_state(self) -> None:
        stale_keys = [
            key
            for key, last_seen in self.last_seen_window.items()
            if self.window_index - last_seen > self.thresholds.retention_windows
        ]
        for key in stale_keys:
            self.history.pop(key, None)
            self.last_seen_window.pop(key, None)


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
