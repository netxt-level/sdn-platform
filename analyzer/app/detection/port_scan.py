from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from .common import clamp_score, current_time, packet_time, score_policy, to_ip, to_port


class PortScanDetector:
    """
    TCP SYN 패턴으로 수직 및 수평 Port Scan 의심 흐름을 탐지한다.

    수직 스캔은 한 대상 IP의 여러 목적지 포트를 확인하는 흐름이고,
    수평 스캔은 여러 대상 IP의 같은 목적지 포트를 확인하는 흐름이다.
    FIN, NULL, XMAS, UDP Scan은 현재 탐지 범위에 포함하지 않는다.
    """

    def __init__(
        self,
        window_sec: int = 5,
        unique_port_threshold: int = 20,
        syn_count_threshold: int = 30,
        multi_target_window_sec: int = 30,
        high_unique_dst_port_threshold: int = 50,
        horizontal_target_threshold: int = 3,
        trusted_source_ips: set[str] | None = None,
        trusted_horizontal_target_threshold: int = 10,
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
        self.trusted_source_ips = trusted_source_ips or set()
        self.trusted_horizontal_target_threshold = trusted_horizontal_target_threshold

        # 같은 흐름을 매 분석 주기마다 반복 보고하지 않도록 잠깐 묶어 둔다.
        self.alert_cooldown_sec = alert_cooldown_sec
        # 패킷을 하나씩 오래 들고 있지 않고, 초 단위 버킷에 필요한 집계만 보관한다.
        self.buckets: dict[int, dict[str, Any]] = {}
        self.last_alert_at: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.last_event_time: datetime | None = None

    def detect(self, packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = current_time()
        latest_packet_time = None

        for packet in packets:
            if not self._is_syn_probe(packet):
                continue

            src_ip = to_ip(packet.get("src_ip"))
            dst_ip = to_ip(packet.get("dst_ip"))
            dst_port = to_port(packet.get("dst_port"))
            if not src_ip or not dst_ip or dst_port is None:
                continue

            event_time = packet_time(packet, now)
            if latest_packet_time is None or event_time > latest_packet_time:
                latest_packet_time = event_time

            bucket = self._bucket_for(event_time)
            pair = (src_ip, dst_ip)
            vertical_stats = bucket["vertical"][pair]
            vertical_stats["ports"].add(dst_port)
            vertical_stats["syn_count"] += 1
            vertical_stats["targets"].add(dst_ip)

            horizontal_stats = bucket["horizontal"][(src_ip, dst_port)]
            horizontal_stats["targets"].add(dst_ip)
            horizontal_stats["syn_count"] += 1

        analysis_time = self._advance_event_time(latest_packet_time, now)
        self._expire_old_buckets(analysis_time)
        self._cleanup_alert_cache(analysis_time)
        vertical_alerts = self._build_vertical_alerts(analysis_time)
        horizontal_alerts = self._build_horizontal_alerts(analysis_time)
        return vertical_alerts + horizontal_alerts

    def _is_syn_probe(self, packet: dict[str, Any]) -> bool:
        # SYN만 있고 ACK가 없는 TCP 패킷을 연결 시도 패턴으로 본다.
        if packet.get("protocol") != "TCP":
            return False

        flags = str(packet.get("tcp_flags") or "").upper()
        return "S" in flags and "A" not in flags

    def _bucket_for(self, timestamp) -> dict[str, Any]:
        bucket_key = int(timestamp.timestamp())
        bucket = self.buckets.get(bucket_key)
        if bucket is None:
            bucket = {
                "vertical": defaultdict(
                    lambda: {"ports": set(), "syn_count": 0, "targets": set()}
                ),
                "horizontal": defaultdict(
                    lambda: {"targets": set(), "syn_count": 0}
                ),
            }
            self.buckets[bucket_key] = bucket
        return bucket

    def _build_vertical_alerts(self, now) -> list[dict[str, Any]]:
        cutoff_key = int((now - timedelta(seconds=self.window_sec)).timestamp())
        grouped = defaultdict(lambda: {"ports": set(), "syn_count": 0})
        # 같은 출발지가 동시에 여러 대상을 훑었는지 설명용 evidence로 남긴다.
        targets_by_source = defaultdict(set)

        for bucket_key, bucket in self.buckets.items():
            if bucket_key < cutoff_key:
                continue

            for pair, bucket_stats in bucket["vertical"].items():
                grouped[pair]["ports"].update(bucket_stats["ports"])
                grouped[pair]["syn_count"] += bucket_stats["syn_count"]
                targets_by_source[pair[0]].update(bucket_stats["targets"])

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
        cutoff_key = int(
            (now - timedelta(seconds=self.multi_target_window_sec)).timestamp()
        )
        grouped = defaultdict(lambda: {"targets": set(), "syn_count": 0})

        for bucket_key, bucket in self.buckets.items():
            if bucket_key < cutoff_key:
                continue

            for key, bucket_stats in bucket["horizontal"].items():
                grouped[key]["targets"].update(bucket_stats["targets"])
                grouped[key]["syn_count"] += bucket_stats["syn_count"]

        alerts = []
        for (src_ip, dst_port), stats in grouped.items():
            target_count = len(stats["targets"])
            threshold = self._horizontal_threshold(src_ip)
            min_syn_count = self._horizontal_min_syn_count(
                target_count=target_count,
            )
            if not self._is_horizontal_candidate(
                src_ip=src_ip,
                target_count=target_count,
                syn_count=stats["syn_count"],
            ):
                continue

            conditions = [
                "TCP SYN 패킷",
                "ACK 없이 연결 시도",
                "여러 대상 IP의 동일 포트 접근",
            ]
            score = 50

            if stats["syn_count"] >= min_syn_count:
                conditions.append("수평 스캔 최소 SYN 수 기준 충족")

            if stats["syn_count"] >= self.syn_count_threshold:
                conditions.append("SYN 시도 수 기준 초과")
                score += 10

            if src_ip in self.trusted_source_ips:
                conditions.append("관리 호스트 기준 적용")
                if target_count < threshold:
                    conditions.append("관리 호스트 반복 SYN 기준 충족")

            if target_count >= threshold * 2:
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
                horizontal_min_syn_count=min_syn_count,
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
        horizontal_min_syn_count: int | None = None,
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
            and (now - last_alert["timestamp"]).total_seconds() < self.alert_cooldown_sec
            and not self._is_escalated_alert(
                score=score,
                severity=severity,
                response_level=response_level,
                last_alert=last_alert,
            )
        ):
            return None

        self.last_alert_at[key] = {
            "timestamp": now,
            "score": score,
            "severity": severity,
            "response_level": response_level,
        }
        evidence = {
            "window_seconds": window_seconds,
            "unique_dst_port_count": len(ports),
            "unique_dst_ports": sorted(ports),
            "syn_count": syn_count,
            "scan_type": scan_type,
            "target_count": target_count,
            "target_ips": target_ips,
        }
        if horizontal_min_syn_count is not None:
            evidence["horizontal_min_syn_count"] = horizontal_min_syn_count

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
            "evidence": evidence,
        }

    def _expire_old_buckets(self, now) -> None:
        retention_sec = max(self.window_sec, self.multi_target_window_sec)
        cutoff_key = int((now - timedelta(seconds=retention_sec)).timestamp())

        for bucket_key in list(self.buckets):
            if bucket_key < cutoff_key:
                self.buckets.pop(bucket_key, None)

    def _cleanup_alert_cache(self, now) -> None:
        # cooldown 기록도 오래 지나면 제거해 장시간 실행 시 메모리 증가를 줄인다.
        retention_sec = self.alert_cooldown_sec * 2
        stale_keys = [
            key
            for key, record in self.last_alert_at.items()
            if (now - record["timestamp"]).total_seconds() > retention_sec
        ]
        for key in stale_keys:
            self.last_alert_at.pop(key, None)

    def _advance_event_time(
        self,
        latest_packet_time: datetime | None,
        fallback_time: datetime,
    ) -> datetime:
        if latest_packet_time is None:
            return self.last_event_time or fallback_time

        if self.last_event_time is None or latest_packet_time > self.last_event_time:
            self.last_event_time = latest_packet_time

        return self.last_event_time

    def _horizontal_threshold(self, src_ip: str) -> int:
        if src_ip in self.trusted_source_ips:
            return self.trusted_horizontal_target_threshold
        return self.horizontal_target_threshold

    def _is_horizontal_candidate(
        self,
        *,
        src_ip: str,
        target_count: int,
        syn_count: int,
    ) -> bool:
        threshold = self._horizontal_threshold(src_ip)
        min_syn_count = self._horizontal_min_syn_count(
            target_count=target_count,
        )
        if target_count >= threshold and syn_count >= min_syn_count:
            return True
        if src_ip not in self.trusted_source_ips:
            return False
        return (
            target_count >= self.horizontal_target_threshold
            and syn_count >= self.syn_count_threshold
        )

    def _horizontal_min_syn_count(self, *, target_count: int) -> int:
        # Mininet처럼 작은 토폴로지는 대상 수 기준이 낮아 정상 점검과 헷갈릴 수 있다.
        # 대상별 1회 SYN만으로는 알림을 만들지 않도록 최소 시도 수를 함께 확인한다.
        return max(
            target_count,
            min(self.syn_count_threshold, target_count * 2),
        )

    def _is_escalated_alert(
        self,
        *,
        score: int,
        severity: str,
        response_level: str,
        last_alert: dict[str, Any],
    ) -> bool:
        return (
            score > int(last_alert.get("score") or 0)
            or _severity_rank(severity) > _severity_rank(str(last_alert.get("severity")))
            or _response_level_rank(response_level)
            > _response_level_rank(str(last_alert.get("response_level")))
        )


def _severity_rank(value: str) -> int:
    return {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }.get(value, 0)


def _response_level_rank(value: str) -> int:
    return {
        "L0": 0,
        "L1": 1,
        "L2": 2,
        "L3": 3,
    }.get(value, 0)
