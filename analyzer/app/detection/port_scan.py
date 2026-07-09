from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any


class PortScanDetector:
    """Detect TCP SYN attempts directed at many ports in a short period."""

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

        # Keep SYN events in time order for both scan windows.
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

        self._expire_old_state(now)
        return self._build_alerts(now)

    def _build_alerts(self, now: datetime) -> list[dict[str, Any]]:
        scan_cutoff = now - timedelta(seconds=self.window_sec)
        multi_target_cutoff = now - timedelta(seconds=self.multi_target_window_sec)
        ports_by_pair: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {"ports": set(), "syn_count": 0}
        )
        scan_targets_by_source: dict[str, set[str]] = defaultdict(set)

        for event in self.events:
            pair = (event["src_ip"], event["dst_ip"])
            if event["timestamp"] >= scan_cutoff:
                ports_by_pair[pair]["ports"].add(event["dst_port"])
                ports_by_pair[pair]["syn_count"] += 1
            if event["timestamp"] >= multi_target_cutoff:
                scan_targets_by_source[event["src_ip"]].add(event["dst_ip"])

        alerts = []
        for (src_ip, dst_ip), stats in ports_by_pair.items():
            ports = stats["ports"]
            syn_count = stats["syn_count"]
            if len(ports) < self.unique_port_threshold:
                continue

            alert_key = (src_ip, dst_ip)
            last_alert = self.last_alert_at.get(alert_key)
            if (
                last_alert is not None
                and (now - last_alert).total_seconds() < self.alert_cooldown_sec
            ):
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
        has_auxiliary_condition = len(matched_conditions) > 3
        response_level = "L2" if has_auxiliary_condition else "L1"
        recommended_action = "alert" if has_auxiliary_condition else "monitor"

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

    def _expire_old_state(self, now: datetime) -> None:
        retention_sec = max(self.window_sec, self.multi_target_window_sec)
        event_cutoff = now - timedelta(seconds=retention_sec)
        alert_cutoff = now - timedelta(seconds=self.alert_cooldown_sec)

        while self.events and self.events[0]["timestamp"] < event_cutoff:
            self.events.popleft()

        expired_alerts = [
            key
            for key, alerted_at in self.last_alert_at.items()
            if alerted_at < alert_cutoff
        ]
        for key in expired_alerts:
            self.last_alert_at.pop(key, None)


def _is_tcp_syn_probe(packet: dict[str, Any]) -> bool:
    if packet.get("protocol") != "TCP":
        return False

    flags = str(packet.get("tcp_flags") or "").upper()
    return "S" in flags and "A" not in flags


def _coerce_dst_port(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
