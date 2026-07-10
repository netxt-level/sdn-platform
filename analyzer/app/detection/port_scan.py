from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Any

from .common import clamp_score, current_time, packet_time, score_policy, to_port


class PortScanDetector:
    """TCP SYN 패턴을 기준으로 Port Scan 의심 흐름을 탐지한다."""

    def __init__(
        self,
        window_sec: int = 5,
        unique_port_threshold: int = 20,
        syn_count_threshold: int = 30,
        multi_target_window_sec: int = 30,
        high_unique_dst_port_threshold: int = 50,
        horizontal_target_threshold: int = 3,
        alert_cooldown_sec: int = 60,
    ) -> None:
        # 수직 스캔은 한 대상 IP의 여러 포트를 짧은 시간에 확인하는 패턴이다.
        self.window_sec = window_sec
        self.unique_port_threshold = unique_port_threshold
        self.syn_count_threshold = syn_count_threshold
        self.high_unique_dst_port_threshold = high_unique_dst_port_threshold

        # 수평 스캔은 여러 대상 IP의 같은 포트를 훑는 패턴이다.
        self.multi_target_window_sec = multi_target_window_sec
        self.horizontal_target_threshold = horizontal_target_threshold

        # 같은 흐름을 매 분석 주기마다 반복 보고하지 않도록 잠깐 묶어 둔다.
        self.alert_cooldown_sec = alert_cooldown_sec
        self.events: deque[dict[str, Any]] = deque()
        self.last_alert_at: dict[tuple[str, str, str], Any] = {}

    def detect(self, packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = current_time()

        for packet in packets:
            if not self._is_syn_probe(packet):
                continue

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            dst_port = to_port(packet.get("dst_port"))
            if not src_ip or not dst_ip or dst_port is None:
                continue

            self.events.append(
                {
                    "timestamp": packet_time(packet, now),
                    "src_ip": str(src_ip),
                    "dst_ip": str(dst_ip),
                    "dst_port": dst_port,
                }
            )

        self._expire_old_events(now)
        self._cleanup_alert_cache(now)
        vertical_alerts = self._build_vertical_alerts(now)
        horizontal_alerts = self._build_horizontal_alerts(now)
        return vertical_alerts + horizontal_alerts

    def _is_syn_probe(self, packet: dict[str, Any]) -> bool:
        # SYN만 있고 ACK가 없는 TCP 패킷을 연결 시도 패턴으로 본다.
        if packet.get("protocol") != "TCP":
            return False

        flags = str(packet.get("tcp_flags") or "").upper()
        return "S" in flags and "A" not in flags

    def _build_vertical_alerts(self, now) -> list[dict[str, Any]]:
        cutoff = now - timedelta(seconds=self.window_sec)
        grouped = defaultdict(lambda: {"ports": set(), "syn_count": 0})
        targets_by_source = defaultdict(set)

        for event in self.events:
            if event["timestamp"] < cutoff:
                continue

            pair = (event["src_ip"], event["dst_ip"])
            grouped[pair]["ports"].add(event["dst_port"])
            grouped[pair]["syn_count"] += 1
            targets_by_source[event["src_ip"]].add(event["dst_ip"])

        alerts = []
        for (src_ip, dst_ip), stats in grouped.items():
            ports = stats["ports"]
            port_count = len(ports)
            if port_count < self.unique_port_threshold:
                continue

            conditions = [
                "TCP SYN 패킷",
                "ACK 없이 연결 시도",
                "단일 대상의 고유 목적지 포트 기준 초과",
            ]
            score = 50

            if stats["syn_count"] >= self.syn_count_threshold:
                conditions.append("SYN 시도 수 기준 초과")
                score += 10

            if port_count >= self.high_unique_dst_port_threshold:
                conditions.append("매우 많은 목적지 포트 접근")
                score += 20

            score = clamp_score(score)
            severity, response_level, recommended_action = score_policy(
                score,
                drop_allowed=False,
            )
            alert = self._make_alert(
                now=now,
                key=(src_ip, dst_ip, "vertical"),
                src_ip=src_ip,
                dst_ip=dst_ip,
                scan_type="vertical",
                ports=ports,
                syn_count=stats["syn_count"],
                target_count=len(targets_by_source[src_ip]),
                conditions=conditions,
                score=score,
                severity=severity,
                response_level=response_level,
                recommended_action=recommended_action,
                target_ips=[dst_ip],
                window_seconds=self.window_sec,
            )
            if alert is not None:
                alerts.append(alert)

        return alerts

    def _build_horizontal_alerts(self, now) -> list[dict[str, Any]]:
        cutoff = now - timedelta(seconds=self.multi_target_window_sec)
        grouped = defaultdict(lambda: {"targets": set(), "syn_count": 0})

        for event in self.events:
            if event["timestamp"] < cutoff:
                continue

            key = (event["src_ip"], event["dst_port"])
            grouped[key]["targets"].add(event["dst_ip"])
            grouped[key]["syn_count"] += 1

        alerts = []
        for (src_ip, dst_port), stats in grouped.items():
            target_count = len(stats["targets"])
            if target_count < self.horizontal_target_threshold:
                continue

            conditions = [
                "TCP SYN 패킷",
                "ACK 없이 연결 시도",
                "여러 대상 IP의 동일 포트 접근",
            ]
            score = 50

            if stats["syn_count"] >= self.syn_count_threshold:
                conditions.append("SYN 시도 수 기준 초과")
                score += 10

            if target_count >= self.horizontal_target_threshold * 2:
                conditions.append("대상 IP 수가 높은 기준 초과")
                score += 20

            score = clamp_score(score)
            severity, response_level, recommended_action = score_policy(
                score,
                drop_allowed=False,
            )
            target_ips = sorted(stats["targets"])
            dst_ip = target_ips[0]
            alert = self._make_alert(
                now=now,
                key=(src_ip, str(dst_port), "horizontal"),
                src_ip=src_ip,
                dst_ip=dst_ip,
                scan_type="horizontal",
                ports={dst_port},
                syn_count=stats["syn_count"],
                target_count=target_count,
                conditions=conditions,
                score=score,
                severity=severity,
                response_level=response_level,
                recommended_action=recommended_action,
                target_ips=target_ips,
                window_seconds=self.multi_target_window_sec,
            )
            if alert is not None:
                alerts.append(alert)

        return alerts

    def _make_alert(
        self,
        *,
        now,
        key: tuple[str, str, str],
        src_ip: str,
        dst_ip: str,
        scan_type: str,
        ports: set[int],
        syn_count: int,
        target_count: int,
        conditions: list[str],
        score: int,
        severity: str,
        response_level: str,
        recommended_action: str,
        target_ips: list[str],
        window_seconds: int,
    ) -> dict[str, Any] | None:
        last_alert = self.last_alert_at.get(key)
        if (
            last_alert is not None
            and (now - last_alert).total_seconds() < self.alert_cooldown_sec
        ):
            return None

        self.last_alert_at[key] = now
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "TCP",
            "attack_category": "RECON",
            "attack_type": "PORT_SCAN",
            "severity": severity,
            "confidence": "high" if score >= 70 else "medium",
            "detection_rule": "tcp_syn_port_scan",
            "recommended_action": recommended_action,
            "response_level": response_level,
            "matched_conditions": conditions,
            "score": score,
            "evidence": {
                "window_seconds": window_seconds,
                "unique_dst_port_count": len(ports),
                "unique_dst_ports": sorted(ports),
                "syn_count": syn_count,
                "scan_type": scan_type,
                "target_count": target_count,
                "target_ips": target_ips,
            },
        }

    def _expire_old_events(self, now) -> None:
        retention_sec = max(self.window_sec, self.multi_target_window_sec)
        cutoff = now - timedelta(seconds=retention_sec)

        self.events = deque(
            event for event in self.events if event["timestamp"] >= cutoff
        )

    def _cleanup_alert_cache(self, now) -> None:
        # cooldown 기록도 오래 지나면 제거해 장시간 실행 시 메모리 증가를 줄인다.
        retention_sec = self.alert_cooldown_sec * 2
        stale_keys = [
            key
            for key, timestamp in self.last_alert_at.items()
            if (now - timestamp).total_seconds() > retention_sec
        ]
        for key in stale_keys:
            self.last_alert_at.pop(key, None)
