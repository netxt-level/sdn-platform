from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any


class PortScanDetector:
    """TCP SYN 패턴을 기준으로 Port Scan 의심 트래픽을 찾는다.

    SYN은 있고 ACK는 없는 패킷을 연결 시도로 보고, 같은 출발지가 짧은 시간 안에
    여러 목적지 포트로 접근하면 스캔 의심 알림을 만든다. 이 결과는 대시보드의
    의심 호스트 목록에도 쓰이고, 보안 이벤트 근거로도 사용할 수 있다.
    """

    def __init__(
        self,
        window_sec: int = 5,
        unique_port_threshold: int = 20,
        syn_count_threshold: int = 20,
        multi_target_window_sec: int = 30,
        multi_target_threshold: int = 3,
        high_unique_dst_port_threshold: int = 50,
        alert_cooldown_sec: int = 60,
    ) -> None:
        self.window_sec = window_sec
        self.unique_port_threshold = unique_port_threshold
        self.syn_count_threshold = syn_count_threshold
        self.multi_target_window_sec = multi_target_window_sec
        self.multi_target_threshold = multi_target_threshold
        self.high_unique_dst_port_threshold = high_unique_dst_port_threshold
        self.alert_cooldown_sec = alert_cooldown_sec

        self.events: deque[dict[str, Any]] = deque()
        self.last_alert_at: dict[tuple[str, str], datetime] = {}

    def detect(self, packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = datetime.now()

        for packet in packets:
            if not _is_tcp_syn_probe(packet):
                continue

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            dst_port = _coerce_dst_port(packet.get("dst_port"))
            if not src_ip or not dst_ip or dst_port is None:
                continue

            self.events.append(
                {
                    "timestamp": now,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                }
            )

        self._expire_old_events(now)
        return self._build_alerts(now)

    def _build_alerts(self, now: datetime) -> list[dict[str, Any]]:
        scan_window_cutoff = now - timedelta(seconds=self.window_sec)
        multi_target_cutoff = now - timedelta(seconds=self.multi_target_window_sec)
        ports_by_pair: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {"ports": set(), "syn_count": 0}
        )
        scan_targets_by_source: dict[str, set[str]] = defaultdict(set)

        for event in self.events:
            key = (event["src_ip"], event["dst_ip"])

            if event["timestamp"] >= scan_window_cutoff:
                ports_by_pair[key]["ports"].add(event["dst_port"])
                ports_by_pair[key]["syn_count"] += 1

            if event["timestamp"] >= multi_target_cutoff:
                scan_targets_by_source[event["src_ip"]].add(event["dst_ip"])

        alerts: list[dict[str, Any]] = []
        for (src_ip, dst_ip), stats in ports_by_pair.items():
            ports = stats["ports"]
            syn_count = stats["syn_count"]

            if len(ports) < self.unique_port_threshold:
                continue

            alert_key = (src_ip, dst_ip)
            last_alert = self.last_alert_at.get(alert_key)
            if last_alert and (now - last_alert).total_seconds() < self.alert_cooldown_sec:
                continue

            self.last_alert_at[alert_key] = now
            alerts.append(
                self._build_alert(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ports=ports,
                    syn_count=syn_count,
                    scanned_target_count=len(scan_targets_by_source[src_ip]),
                )
            )

        return alerts

    def _build_alert(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        ports: set[int],
        syn_count: int,
        scanned_target_count: int,
    ) -> dict[str, Any]:
        matched_conditions = [
            "tcp_syn_without_ack",
            "same_source_target_pair",
            "unique_dst_port_threshold_exceeded",
        ]
        score = 60

        if syn_count >= self.syn_count_threshold:
            matched_conditions.append("syn_count_threshold_satisfied")
            score += 10

        if scanned_target_count >= self.multi_target_threshold:
            matched_conditions.append("multi_target_scan")
            score += 15

        if len(ports) >= self.high_unique_dst_port_threshold:
            matched_conditions.append("high_unique_dst_port_count")
            score += 15

        score = min(score, 100)
        response_level = "L2" if score >= 70 else "L1"
        recommended_action = "alert" if response_level == "L2" else "monitor"

        return {
            "host": src_ip,
            "ip": src_ip,
            "protocol": "TCP",
            "bps": 0,
            "pps": 0,
            "attack_type": "PORT_SCAN",
            "reasons": ["Port Scan"],
            "target_ip": dst_ip,
            "window_seconds": self.window_sec,
            "unique_dst_port_count": len(ports),
            "unique_dst_ports": sorted(ports),
            "syn_count": syn_count,
            "matched_conditions": matched_conditions,
            "score": score,
            "response_level": response_level,
            "recommended_action": recommended_action,
        }

    def _expire_old_events(self, now: datetime) -> None:
        retention_sec = max(self.window_sec, self.multi_target_window_sec)
        cutoff = now - timedelta(seconds=retention_sec)

        while self.events and self.events[0]["timestamp"] < cutoff:
            self.events.popleft()


def _is_tcp_syn_probe(packet: dict[str, Any]) -> bool:
    if packet.get("protocol") != "TCP":
        return False

    flags = str(packet.get("tcp_flags", "")).upper()
    return "S" in flags and "A" not in flags


def _coerce_dst_port(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
