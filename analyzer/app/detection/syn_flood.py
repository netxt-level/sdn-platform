from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from .common import clamp_score, score_policy, to_port


class SynFloodDetector:
    """특정 서비스로 SYN 패킷이 몰리는 패턴을 탐지한다."""

    def __init__(
        self,
        pps_threshold: float = 300,
        high_pps_threshold: float = 1000,
        critical_pps_threshold: float = 2000,
        max_unique_ports: int = 5,
        minimum_syn_count: int = 30,
        history_size: int = 3,
        required_exceeded_windows: int = 2,
        retention_windows: int = 120,
    ) -> None:
        # SYN Flood는 특정 목적지 IP와 포트에 연결 시도가 집중되는지가 핵심이다.
        self.pps_threshold = pps_threshold
        self.high_pps_threshold = high_pps_threshold
        self.critical_pps_threshold = critical_pps_threshold
        self.max_unique_ports = max_unique_ports
        self.minimum_syn_count = minimum_syn_count
        self.required_exceeded_windows = required_exceeded_windows
        self.retention_windows = retention_windows

        # 단발성 증가를 바로 공격으로 보지 않기 위해 최근 탐지 구간 결과를 보관한다.
        self.histories: dict[tuple[str, str, int], deque[bool]] = defaultdict(
            lambda: deque(maxlen=history_size)
        )
        self.window_index = 0
        self.last_seen_window: dict[tuple[str, str, int], int] = {}

    def detect(
        self,
        packets: list[dict[str, Any]],
        window_sec: int | float,
    ) -> list[dict[str, Any]]:
        self.window_index += 1
        divisor = float(window_sec) if window_sec and window_sec > 0 else 1.0
        syn_groups = defaultdict(lambda: {"syn": 0, "src_ports": set()})
        response_counts: dict[tuple[str, str, int], int] = defaultdict(int)
        dst_ports_by_pair = defaultdict(set)

        for packet in packets:
            if packet.get("protocol") != "TCP":
                continue

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            if not src_ip or not dst_ip:
                continue

            src_ip = str(src_ip)
            dst_ip = str(dst_ip)
            src_port = to_port(packet.get("src_port"))
            dst_port = to_port(packet.get("dst_port"))
            flags = str(packet.get("tcp_flags") or "").upper()

            # SYN만 있고 ACK가 없는 패킷은 연결 시작 요청으로 본다.
            if "S" in flags and "A" not in flags:
                if dst_port is None:
                    continue
                key = (src_ip, dst_ip, dst_port)
                syn_groups[key]["syn"] += 1
                dst_ports_by_pair[(src_ip, dst_ip)].add(dst_port)
                if src_port is not None:
                    syn_groups[key]["src_ports"].add(src_port)
                continue

            # SYN/ACK는 서버에서 클라이언트로 돌아오므로 역방향 흐름으로 보정한다.
            if "S" in flags and "A" in flags and src_port is not None:
                response_counts[(dst_ip, src_ip, src_port)] += 1

        alerts: list[dict[str, Any]] = []
        for (src_ip, dst_ip, dst_port), stats in syn_groups.items():
            unique_dst_ports = len(dst_ports_by_pair[(src_ip, dst_ip)])

            # 여러 포트를 넓게 훑는 흐름은 Port Scan 탐지기가 담당하게 둔다.
            if unique_dst_ports > self.max_unique_ports:
                continue

            syn_count = stats["syn"]
            response_count = response_counts.get((src_ip, dst_ip, dst_port), 0)
            syn_pps = syn_count / divisor
            syn_response_ratio = syn_count / max(response_count, 1)
            response_shortage = syn_response_ratio >= 4
            exceeded = (
                syn_pps >= self.pps_threshold
                and syn_count >= self.minimum_syn_count
                and response_shortage
            )

            # 중간에 빈 구간이 있으면 이전 SYN 증가 기록을 이어 붙이지 않는다.
            key = (src_ip, dst_ip, dst_port)
            history = self.histories[key]
            last_seen = self.last_seen_window.get(key)
            if last_seen is not None and last_seen < self.window_index - 1:
                history.clear()
            history.append(exceeded)
            self.last_seen_window[key] = self.window_index
            exceeded_windows = sum(history)

            immediate_critical = (
                syn_pps >= self.critical_pps_threshold and response_shortage
            )
            sustained = (
                exceeded
                and exceeded_windows >= self.required_exceeded_windows
            )
            if not immediate_critical and not sustained:
                continue

            conditions = [
                "TCP SYN 패킷",
                "단일 서비스로 SYN 집중",
            ]
            score = 40

            if syn_pps >= self.pps_threshold:
                conditions.append("SYN PPS 기준 초과")
                score += 15
            if syn_count >= self.minimum_syn_count:
                conditions.append("최소 SYN 수 기준 충족")
            if exceeded_windows >= self.required_exceeded_windows:
                conditions.append("여러 분석 구간에서 반복 초과")
                score += 10
            if response_shortage:
                conditions.append("SYN 대비 응답 부족(보조 지표)")
                score += 10
            if syn_pps >= self.high_pps_threshold:
                conditions.append("높은 SYN PPS 기준 초과")
                score += 10
            if immediate_critical:
                conditions.append("Critical SYN PPS 기준 즉시 초과")
                score = 90

            score = clamp_score(score)
            severity, response_level, recommended_action = score_policy(
                score,
                drop_allowed=sustained,
            )
            alerts.append(
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": "TCP",
                    "attack_category": "FLOOD",
                    "attack_type": "SYN_FLOOD",
                    "severity": severity,
                    "confidence": (
                        "high" if immediate_critical or sustained else "medium"
                    ),
                    "detection_rule": "tcp_syn_single_service_rate",
                    "recommended_action": recommended_action,
                    "response_level": response_level,
                    "matched_conditions": conditions,
                    "score": score,
                    "evidence": {
                        "window_seconds": divisor,
                        "destination_port": dst_port,
                        "syn_count": syn_count,
                        "response_count": response_count,
                        "syn_pps": syn_pps,
                        "syn_response_ratio": syn_response_ratio,
                        "response_shortage": response_shortage,
                        "unique_dst_port_count": unique_dst_ports,
                        "unique_src_port_count": len(stats["src_ports"]),
                        "pps_threshold": self.pps_threshold,
                        "high_pps_threshold": self.high_pps_threshold,
                        "critical_pps_threshold": self.critical_pps_threshold,
                        "exceeded_windows": exceeded_windows,
                        "required_exceeded_windows": (
                            self.required_exceeded_windows
                        ),
                        "drop_allowed": sustained,
                    },
                }
            )

        self._cleanup_state()
        return alerts

    def _cleanup_state(self) -> None:
        stale_keys = [
            key
            for key, last_seen in self.last_seen_window.items()
            if self.window_index - last_seen > self.retention_windows
        ]
        for key in stale_keys:
            self.histories.pop(key, None)
            self.last_seen_window.pop(key, None)
