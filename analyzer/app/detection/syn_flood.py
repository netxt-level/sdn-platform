from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from .common import current_time, packet_time
from .common import clamp_score, score_policy, to_ip, to_port


class SynFloodDetector:
    """
    SYN 패킷이 몰리고 TCP 연결이 끝까지 완료되지 않는 Flood 의심 흐름을 탐지한다.

    기본은 단일 서비스 집중 패턴을 보며, 여러 포트로 나뉜 SYN이
    Port Scan처럼 보이더라도 연결 완료율이 낮고 전체 SYN 양이 크면
    다중 서비스 SYN Flood로 묶어서 판단한다.
    현재 대응 후보는 IPv4 OpenFlow match 기준으로 생성된다.
    """

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
        # SYN Flood는 SYN 증가와 최종 ACK 완료율 부족을 함께 보는 것이 핵심이다.
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
        self.last_seen_bucket: dict[tuple[str, str, int], int] = {}
        self.last_bucket_stats: dict[tuple[str, str, int], dict[str, Any]] = {}
        self.last_bucket_response_counts: dict[tuple[str, str, int], int] = {}
        self.last_bucket_completed_counts: dict[tuple[str, str, int], int] = {}
        self.last_bucket_unique_dst_ports: dict[tuple[str, str, int], int] = {}

    def detect(
        self,
        packets: list[dict[str, Any]],
        window_sec: int | float,
    ) -> list[dict[str, Any]]:
        divisor = float(window_sec) if window_sec and window_sec > 0 else 1.0
        fallback_time = current_time()
        use_packet_time_bucket = any(
            packet.get("timestamp") is not None
            for packet in packets
        )
        bucket_divisor = 1.0 if use_packet_time_bucket else divisor
        syn_groups_by_bucket = defaultdict(
            lambda: defaultdict(lambda: {"syn": 0, "src_ports": set()})
        )
        pair_groups_by_bucket = defaultdict(
            lambda: defaultdict(
                lambda: {"syn": 0, "dst_ports": set(), "src_ports": set()}
            )
        )
        response_counts_by_bucket = defaultdict(lambda: defaultdict(int))
        pair_response_counts_by_bucket = defaultdict(lambda: defaultdict(int))
        completed_counts_by_bucket = defaultdict(lambda: defaultdict(int))
        pair_completed_counts_by_bucket = defaultdict(lambda: defaultdict(int))

        for packet in packets:
            if packet.get("protocol") != "TCP":
                continue

            src_ip = to_ip(packet.get("src_ip"))
            dst_ip = to_ip(packet.get("dst_ip"))
            if not src_ip or not dst_ip:
                continue

            src_port = to_port(packet.get("src_port"))
            dst_port = to_port(packet.get("dst_port"))
            flags = str(packet.get("tcp_flags") or "").upper()
            bucket_key = None
            if use_packet_time_bucket:
                bucket_key = int(packet_time(packet, fallback_time).timestamp())

            # SYN만 있고 ACK가 없는 패킷은 연결 시작 요청으로 본다.
            if "S" in flags and "A" not in flags:
                if dst_port is None:
                    continue
                key = (src_ip, dst_ip, dst_port)
                syn_groups_by_bucket[bucket_key][key]["syn"] += 1
                pair_groups_by_bucket[bucket_key][(src_ip, dst_ip)]["syn"] += 1
                pair_groups_by_bucket[bucket_key][(src_ip, dst_ip)][
                    "dst_ports"
                ].add(dst_port)
                if src_port is not None:
                    syn_groups_by_bucket[bucket_key][key]["src_ports"].add(src_port)
                    pair_groups_by_bucket[bucket_key][(src_ip, dst_ip)][
                        "src_ports"
                    ].add(src_port)
                continue

            # SYN/ACK는 서버에서 클라이언트로 돌아오므로 역방향 흐름으로 보정한다.
            if "S" in flags and "A" in flags and src_port is not None:
                response_counts_by_bucket[bucket_key][(dst_ip, src_ip, src_port)] += 1
                pair_response_counts_by_bucket[bucket_key][(dst_ip, src_ip)] += 1
                continue

            # SYN/ACK 이후 클라이언트가 보내는 ACK가 있어야 3-way handshake가 완료된다.
            if "A" in flags and "S" not in flags and dst_port is not None:
                completed_counts_by_bucket[bucket_key][(src_ip, dst_ip, dst_port)] += 1
                pair_completed_counts_by_bucket[bucket_key][(src_ip, dst_ip)] += 1

        alerts_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
        bucket_keys = _sorted_bucket_keys(
            syn_groups_by_bucket,
            pair_groups_by_bucket,
            response_counts_by_bucket,
            pair_response_counts_by_bucket,
            completed_counts_by_bucket,
            pair_completed_counts_by_bucket,
        )
        if not bucket_keys:
            self.window_index += 1
            self._cleanup_state()
            return []

        for bucket_start_epoch in bucket_keys:
            self.window_index += 1
            syn_groups = syn_groups_by_bucket[bucket_start_epoch]
            pair_groups = pair_groups_by_bucket[bucket_start_epoch]
            response_counts = response_counts_by_bucket[bucket_start_epoch]
            pair_response_counts = pair_response_counts_by_bucket[bucket_start_epoch]
            completed_counts = completed_counts_by_bucket[bucket_start_epoch]
            pair_completed_counts = pair_completed_counts_by_bucket[bucket_start_epoch]

            for (src_ip, dst_ip, dst_port), stats in syn_groups.items():
                unique_dst_ports = len(pair_groups[(src_ip, dst_ip)]["dst_ports"])

                # 여러 포트를 넓게 훑는 흐름은 Port Scan 탐지기가 담당하게 둔다.
                if unique_dst_ports > self.max_unique_ports:
                    continue

                alert = self._build_single_service_alert(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    stats=stats,
                    response_count=response_counts.get((src_ip, dst_ip, dst_port), 0),
                    completed_count=completed_counts.get((src_ip, dst_ip, dst_port), 0),
                    unique_dst_ports=unique_dst_ports,
                    divisor=bucket_divisor,
                    analysis_window_seconds=divisor,
                    bucket_start_epoch=bucket_start_epoch,
                )
                if alert is not None:
                    _remember_alert(alerts_by_key, alert)

            for alert in self._build_multi_service_alerts(
                pair_groups=pair_groups,
                pair_response_counts=pair_response_counts,
                pair_completed_counts=pair_completed_counts,
                divisor=bucket_divisor,
                analysis_window_seconds=divisor,
                bucket_start_epoch=bucket_start_epoch,
            ):
                _remember_alert(alerts_by_key, alert)

        self._cleanup_state()
        return list(alerts_by_key.values())

    def _build_single_service_alert(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        stats: dict[str, Any],
        response_count: int,
        completed_count: int,
        unique_dst_ports: int,
        divisor: float,
        analysis_window_seconds: float,
        bucket_start_epoch: int | None,
    ) -> dict[str, Any] | None:
        # 중간에 빈 구간이 있으면 이전 SYN 증가 기록을 이어 붙이지 않는다.
        # 같은 1초 bucket이 여러 번 나뉘어 들어오면 집계만 갱신하고 history는 한 번만 반영한다.
        key = (src_ip, dst_ip, dst_port)
        history = self.histories[key]
        last_seen_window = self.last_seen_window.get(key)
        last_seen_bucket = self.last_seen_bucket.get(key)
        same_bucket = False
        if bucket_start_epoch is not None:
            if last_seen_bucket is not None:
                if bucket_start_epoch < last_seen_bucket:
                    return None
                if bucket_start_epoch == last_seen_bucket:
                    same_bucket = True
                    stats = _merge_syn_stats(self.last_bucket_stats.get(key), stats)
                    response_count += self.last_bucket_response_counts.get(key, 0)
                    completed_count += self.last_bucket_completed_counts.get(key, 0)
                    unique_dst_ports = max(
                        unique_dst_ports,
                        self.last_bucket_unique_dst_ports.get(key, 0),
                    )
                elif bucket_start_epoch - last_seen_bucket > 1:
                    history.clear()
            if not same_bucket:
                stats = _clone_syn_stats(stats)
        elif (
            last_seen_window is not None
            and last_seen_window < self.window_index - 1
        ):
            history.clear()

        syn_count = stats["syn"]
        syn_pps = syn_count / divisor
        syn_response_ratio = syn_count / max(response_count, 1)
        handshake_completion_ratio = completed_count / max(syn_count, 1)
        response_shortage = syn_response_ratio >= 4
        completion_shortage = handshake_completion_ratio < 0.25
        exceeded = (
            syn_pps >= self.pps_threshold
            and syn_count >= self.minimum_syn_count
            and (response_shortage or completion_shortage)
        )

        if same_bucket and history:
            history.pop()
        history.append(exceeded)
        self.last_seen_window[key] = self.window_index
        if bucket_start_epoch is not None:
            self.last_seen_bucket[key] = bucket_start_epoch
            self.last_bucket_stats[key] = stats
            self.last_bucket_response_counts[key] = response_count
            self.last_bucket_completed_counts[key] = completed_count
            self.last_bucket_unique_dst_ports[key] = unique_dst_ports
        else:
            self.last_seen_bucket.pop(key, None)
            self.last_bucket_stats.pop(key, None)
            self.last_bucket_response_counts.pop(key, None)
            self.last_bucket_completed_counts.pop(key, None)
            self.last_bucket_unique_dst_ports.pop(key, None)
        exceeded_windows = sum(history)

        immediate_critical = syn_pps >= self.critical_pps_threshold and (
            response_shortage or completion_shortage
        )
        sustained = (
            exceeded
            and exceeded_windows >= self.required_exceeded_windows
        )
        if not immediate_critical and not sustained:
            return None

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
        if completion_shortage:
            conditions.append("최종 ACK 완료율 부족")
            if not response_shortage:
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
        evidence = {
            "window_seconds": divisor,
            "destination_port": dst_port,
            "syn_count": syn_count,
            "response_count": response_count,
            "completed_count": completed_count,
            "syn_pps": syn_pps,
            "syn_response_ratio": syn_response_ratio,
            "handshake_completion_ratio": handshake_completion_ratio,
            "response_shortage": response_shortage,
            "completion_shortage": completion_shortage,
            "unique_dst_port_count": unique_dst_ports,
            "unique_src_port_count": len(stats["src_ports"]),
            "pps_threshold": self.pps_threshold,
            "high_pps_threshold": self.high_pps_threshold,
            "critical_pps_threshold": self.critical_pps_threshold,
            "exceeded_windows": exceeded_windows,
            "required_exceeded_windows": self.required_exceeded_windows,
            "drop_allowed": sustained,
            "mitigation_stage": "escalated" if sustained else "initial",
            "escalation_reason": (
                "repeated threshold exceeded"
                if sustained
                else "critical rate observed once"
            ),
        }
        if bucket_start_epoch is not None:
            evidence["bucket_start_epoch"] = bucket_start_epoch
            evidence["analysis_window_seconds"] = analysis_window_seconds

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "TCP",
            "attack_category": "FLOOD",
            "attack_type": "SYN_FLOOD",
            "severity": severity,
            "confidence": "high" if immediate_critical or sustained else "medium",
            "detection_rule": "tcp_syn_single_service_rate",
            "recommended_action": recommended_action,
            "response_level": response_level,
            "matched_conditions": conditions,
            "score": score,
            "evidence": evidence,
        }

    def _build_multi_service_alerts(
        self,
        *,
        pair_groups,
        pair_response_counts: dict[tuple[str, str], int],
        pair_completed_counts: dict[tuple[str, str], int],
        divisor: float,
        analysis_window_seconds: float,
        bucket_start_epoch: int | None,
    ) -> list[dict[str, Any]]:
        alerts = []

        for (src_ip, dst_ip), stats in pair_groups.items():
            response_count = pair_response_counts.get((src_ip, dst_ip), 0)
            completed_count = pair_completed_counts.get((src_ip, dst_ip), 0)

            # 포트가 여러 개인 공격은 서비스별로 쪼개면 놓칠 수 있어 출발지-목적지 전체량도 본다.
            # 같은 1초 bucket이 다시 들어온 경우 이전 집계와 합산하되 history는 갱신만 한다.
            key = (src_ip, dst_ip, 0)
            history = self.histories[key]
            last_seen_window = self.last_seen_window.get(key)
            last_seen_bucket = self.last_seen_bucket.get(key)
            same_bucket = False
            if bucket_start_epoch is not None:
                if last_seen_bucket is not None:
                    if bucket_start_epoch < last_seen_bucket:
                        continue
                    if bucket_start_epoch == last_seen_bucket:
                        same_bucket = True
                        stats = _merge_syn_stats(
                            self.last_bucket_stats.get(key),
                            stats,
                        )
                        response_count += self.last_bucket_response_counts.get(key, 0)
                        completed_count += self.last_bucket_completed_counts.get(key, 0)
                    elif bucket_start_epoch - last_seen_bucket > 1:
                        history.clear()
                if not same_bucket:
                    stats = _clone_syn_stats(stats)
            elif (
                last_seen_window is not None
                and last_seen_window < self.window_index - 1
            ):
                history.clear()

            dst_ports = stats["dst_ports"]
            unique_dst_ports = len(dst_ports)
            syn_count = stats["syn"]
            syn_pps = syn_count / divisor
            syn_response_ratio = syn_count / max(response_count, 1)
            handshake_completion_ratio = completed_count / max(syn_count, 1)
            response_shortage = syn_response_ratio >= 4
            completion_shortage = handshake_completion_ratio < 0.25
            multi_service_candidate = unique_dst_ports > self.max_unique_ports
            exceeded = (
                multi_service_candidate
                and syn_pps >= self.pps_threshold
                and syn_count >= self.minimum_syn_count
                and (response_shortage or completion_shortage)
            )

            if same_bucket and history:
                history.pop()
            history.append(exceeded)
            self.last_seen_window[key] = self.window_index
            if bucket_start_epoch is not None:
                self.last_seen_bucket[key] = bucket_start_epoch
                self.last_bucket_stats[key] = stats
                self.last_bucket_response_counts[key] = response_count
                self.last_bucket_completed_counts[key] = completed_count
                self.last_bucket_unique_dst_ports[key] = unique_dst_ports
            else:
                self.last_seen_bucket.pop(key, None)
                self.last_bucket_stats.pop(key, None)
                self.last_bucket_response_counts.pop(key, None)
                self.last_bucket_completed_counts.pop(key, None)
                self.last_bucket_unique_dst_ports.pop(key, None)
            exceeded_windows = sum(history)

            immediate_critical = (
                multi_service_candidate
                and syn_pps >= self.critical_pps_threshold
                and (response_shortage or completion_shortage)
            )
            sustained = (
                exceeded
                and exceeded_windows >= self.required_exceeded_windows
            )
            if not immediate_critical and not sustained:
                continue

            conditions = [
                "TCP SYN 패킷",
                "여러 서비스로 SYN 집중",
            ]
            score = 55
            if response_shortage:
                conditions.append("SYN 대비 응답 부족(보조 지표)")
            if completion_shortage:
                conditions.append("최종 ACK 완료율 부족")
                if not response_shortage:
                    score += 10
            if syn_pps >= self.pps_threshold:
                conditions.append("출발지-목적지 전체 SYN PPS 기준 초과")
                score += 15
            if exceeded_windows >= self.required_exceeded_windows:
                conditions.append("여러 분석 구간에서 반복 초과")
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
            evidence = {
                "window_seconds": divisor,
                "syn_count": syn_count,
                "response_count": response_count,
                "completed_count": completed_count,
                "syn_pps": syn_pps,
                "syn_response_ratio": syn_response_ratio,
                "handshake_completion_ratio": handshake_completion_ratio,
                "response_shortage": response_shortage,
                "completion_shortage": completion_shortage,
                "unique_dst_port_count": unique_dst_ports,
                "sample_dst_ports": sorted(dst_ports)[:10],
                "unique_src_port_count": len(stats["src_ports"]),
                "pps_threshold": self.pps_threshold,
                "high_pps_threshold": self.high_pps_threshold,
                "critical_pps_threshold": self.critical_pps_threshold,
                "exceeded_windows": exceeded_windows,
                "required_exceeded_windows": self.required_exceeded_windows,
                "drop_allowed": sustained,
                "scan_like": True,
                "mitigation_stage": "escalated" if sustained else "initial",
                "escalation_reason": (
                    "repeated threshold exceeded"
                    if sustained
                    else "critical rate observed once"
                ),
            }
            if bucket_start_epoch is not None:
                evidence["bucket_start_epoch"] = bucket_start_epoch
                evidence["analysis_window_seconds"] = analysis_window_seconds
            alerts.append(
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": "TCP",
                    "attack_category": "FLOOD",
                    "attack_type": "SYN_FLOOD",
                    "severity": severity,
                    "confidence": "high" if immediate_critical or sustained else "medium",
                    "detection_rule": "tcp_syn_multi_service_rate",
                    "recommended_action": recommended_action,
                    "response_level": response_level,
                    "matched_conditions": conditions,
                    "score": score,
                    "evidence": evidence,
                }
            )

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
            self.last_seen_bucket.pop(key, None)
            self.last_bucket_stats.pop(key, None)
            self.last_bucket_response_counts.pop(key, None)
            self.last_bucket_completed_counts.pop(key, None)
            self.last_bucket_unique_dst_ports.pop(key, None)


def _sorted_bucket_keys(*grouped_maps) -> list[int | None]:
    keys = set()
    for grouped_map in grouped_maps:
        keys.update(grouped_map.keys())
    return sorted(keys, key=lambda value: -1 if value is None else value)


def _clone_syn_stats(stats: dict[str, Any]) -> dict[str, Any]:
    cloned = {
        "syn": int(stats.get("syn") or 0),
        "src_ports": set(stats.get("src_ports") or set()),
    }
    if "dst_ports" in stats:
        cloned["dst_ports"] = set(stats.get("dst_ports") or set())
    return cloned


def _merge_syn_stats(
    previous: dict[str, Any] | None,
    current: dict[str, Any],
) -> dict[str, Any]:
    merged = _clone_syn_stats(previous or {})
    merged["syn"] += int(current.get("syn") or 0)
    merged["src_ports"].update(current.get("src_ports") or set())
    if "dst_ports" in current or "dst_ports" in merged:
        merged.setdefault("dst_ports", set())
        merged["dst_ports"].update(current.get("dst_ports") or set())
    return merged


def _remember_alert(
    alerts_by_key: dict[tuple[Any, ...], dict[str, Any]],
    alert: dict[str, Any],
) -> None:
    evidence = alert.get("evidence") or {}
    key = (
        alert["detection_rule"],
        alert["src_ip"],
        alert["dst_ip"],
        evidence.get("destination_port"),
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
