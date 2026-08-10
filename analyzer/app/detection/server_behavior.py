from __future__ import annotations

from collections import deque
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from statistics import median
from typing import Any


def _packet_time(packet: dict[str, Any], fallback: datetime) -> datetime:
    value = packet.get("timestamp")
    if value is None:
        return fallback
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return fallback


def _is_tcp_connection_start(packet: dict[str, Any]) -> bool:
    if packet.get("protocol") != "TCP":
        return False
    flags = str(packet.get("tcp_flags") or "")
    return "S" in flags and "A" not in flags


class ServerBehaviorDetector:
    """Detect stateful post-compromise behavior from protected servers."""

    def __init__(
        self,
        *,
        protected_server_ips: set[str] | None = None,
        egress_allowlist: set[str] | None = None,
        connection_retention_sec: int = 600,
        syn_retransmit_suppression_sec: float = 3.0,
        fanout_window_sec: int = 30,
        fanout_unique_dst_threshold: int = 2,
        fanout_connection_threshold: int = 3,
        alert_cooldown_sec: int = 60,
        volume_window_sec: int = 10,
        outbound_bps_threshold: float = 1_000_000,
        outbound_baseline_multiplier: float = 3.0,
        outbound_baseline_samples: int = 60,
        outbound_baseline_min_samples: int = 5,
        outbound_sustained_windows: int = 3,
        beacon_window_sec: int = 300,
        beacon_min_connections: int = 6,
        beacon_min_interval_sec: float = 20.0,
        beacon_max_interval_sec: float = 90.0,
        beacon_max_jitter_ratio: float = 0.2,
    ):
        self.protected_server_ips = protected_server_ips or {"10.0.0.100"}
        self.egress_allowlist = egress_allowlist or set()
        self.connection_retention_sec = max(
            connection_retention_sec,
            fanout_window_sec,
            volume_window_sec,
            beacon_window_sec,
        )
        self.syn_retransmit_suppression_sec = syn_retransmit_suppression_sec
        self.fanout_window_sec = fanout_window_sec
        self.fanout_unique_dst_threshold = fanout_unique_dst_threshold
        self.fanout_connection_threshold = fanout_connection_threshold
        self.alert_cooldown_sec = alert_cooldown_sec
        self.volume_window_sec = volume_window_sec
        self.outbound_bps_threshold = outbound_bps_threshold
        self.outbound_baseline_multiplier = outbound_baseline_multiplier
        self.outbound_baseline_samples = outbound_baseline_samples
        self.outbound_baseline_min_samples = outbound_baseline_min_samples
        self.outbound_sustained_windows = outbound_sustained_windows
        self.beacon_window_sec = beacon_window_sec
        self.beacon_min_connections = beacon_min_connections
        self.beacon_min_interval_sec = beacon_min_interval_sec
        self.beacon_max_interval_sec = beacon_max_interval_sec
        self.beacon_max_jitter_ratio = beacon_max_jitter_ratio
        self.connection_starts: deque[dict[str, Any]] = deque()
        self.outbound_packets: deque[dict[str, Any]] = deque()
        self.last_flow_start: dict[tuple[Any, ...], datetime] = {}
        self.server_initiated_flows: dict[tuple[Any, ...], datetime] = {}
        self.last_alert_at: dict[tuple[str, str], datetime] = {}
        self.volume_baselines: dict[tuple[str, str], deque[float]] = {}
        self.volume_alert_streaks: dict[tuple[str, str], int] = {}

    def detect(
        self,
        packets: list[dict[str, Any]],
        *,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        observed_at = now or datetime.now(timezone.utc)
        new_starts = []
        ordered_packets = sorted(
            packets,
            key=lambda item: _packet_time(item, observed_at),
        )

        for packet in ordered_packets:
            if not _is_tcp_connection_start(packet):
                continue

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            src_port = packet.get("src_port")
            dst_port = packet.get("dst_port")
            if (
                src_ip not in self.protected_server_ips
                or not dst_ip
                or dst_ip in self.egress_allowlist
                or src_port is None
                or dst_port is None
            ):
                continue

            timestamp = _packet_time(packet, observed_at)
            flow_key = (src_ip, dst_ip, int(src_port), int(dst_port))
            previous_start = self.last_flow_start.get(flow_key)
            if (
                previous_start is not None
                and (timestamp - previous_start).total_seconds()
                < self.syn_retransmit_suppression_sec
            ):
                continue

            event = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(src_port),
                "dst_port": int(dst_port),
                "packet_size": _non_negative_int(packet.get("packet_size")),
            }
            self.connection_starts.append(event)
            self.last_flow_start[flow_key] = timestamp
            self.server_initiated_flows[flow_key] = timestamp
            new_starts.append(event)

        volume_keys = self._collect_outbound_packets(
            ordered_packets,
            observed_at,
        )
        self._expire_old_state(observed_at)
        alerts = self._build_role_violation_alerts(new_starts)
        alerts.extend(self._build_fanout_alerts(new_starts, observed_at))
        alerts.extend(self._build_volume_alerts(volume_keys, observed_at))
        alerts.extend(self._build_beacon_alerts(new_starts, observed_at))
        return alerts

    def _build_role_violation_alerts(
        self,
        new_starts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for event in new_starts:
            grouped.setdefault(
                (event["src_ip"], event["dst_ip"]),
                [],
            ).append(event)

        alerts = []
        for (src_ip, dst_ip), events in grouped.items():
            alerts.append({
                "attack_category": "POST_COMPROMISE",
                "attack_type": "SERVER_EGRESS",
                "severity": "high",
                "confidence": "high",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "TCP",
                "detection_rule": "protected_server_tcp_egress",
                "recommended_action": "alert",
                "response_level": "L2",
                "evidence": {
                    "matched_conditions": [
                        "protected_server_source",
                        "tcp_syn_without_ack",
                        "destination_not_allowlisted",
                    ],
                    "connection_count": len(events),
                    "src_ports": sorted({
                        event["src_port"]
                        for event in events
                    }),
                    "dst_ports": sorted({
                        event["dst_port"]
                        for event in events
                    }),
                },
            })
        return alerts

    def _build_fanout_alerts(
        self,
        new_starts: list[dict[str, Any]],
        now: datetime,
    ) -> list[dict[str, Any]]:
        if not new_starts:
            return []

        cutoff = now - timedelta(seconds=self.fanout_window_sec)
        sources_with_new_starts = {
            event["src_ip"]
            for event in new_starts
        }
        alerts = []

        for src_ip in sources_with_new_starts:
            events = [
                event
                for event in self.connection_starts
                if event["src_ip"] == src_ip and event["timestamp"] >= cutoff
            ]
            destinations = sorted({event["dst_ip"] for event in events})
            if (
                len(destinations) < self.fanout_unique_dst_threshold
                or len(events) < self.fanout_connection_threshold
            ):
                continue

            alert_key = ("LATERAL_MOVEMENT", src_ip)
            last_alert = self.last_alert_at.get(alert_key)
            if (
                last_alert is not None
                and (now - last_alert).total_seconds() < self.alert_cooldown_sec
            ):
                continue
            self.last_alert_at[alert_key] = now

            latest_event = max(events, key=lambda event: event["timestamp"])
            alerts.append({
                "attack_category": "POST_COMPROMISE",
                "attack_type": "LATERAL_MOVEMENT",
                "severity": "critical",
                "confidence": "high",
                "src_ip": src_ip,
                "dst_ip": latest_event["dst_ip"],
                "protocol": "TCP",
                "detection_rule": "protected_server_destination_fanout",
                "recommended_action": "drop",
                "response_level": "L3",
                "evidence": {
                    "matched_conditions": [
                        "protected_server_source",
                        "tcp_syn_without_ack",
                        "unique_destination_threshold_exceeded",
                        "connection_attempt_threshold_exceeded",
                    ],
                    "window_seconds": self.fanout_window_sec,
                    "connection_count": len(events),
                    "connection_threshold": self.fanout_connection_threshold,
                    "unique_dst_ip_count": len(destinations),
                    "unique_dst_ip_threshold": (
                        self.fanout_unique_dst_threshold
                    ),
                    "destination_ips": destinations,
                },
            })

        return alerts

    def _collect_outbound_packets(
        self,
        packets: list[dict[str, Any]],
        now: datetime,
    ) -> set[tuple[str, str]]:
        observed_keys = set()

        for packet in packets:
            if packet.get("protocol") != "TCP":
                continue

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            src_port = packet.get("src_port")
            dst_port = packet.get("dst_port")
            if (
                src_ip not in self.protected_server_ips
                or not dst_ip
                or dst_ip in self.egress_allowlist
                or src_port is None
                or dst_port is None
            ):
                continue

            flow_key = (src_ip, dst_ip, int(src_port), int(dst_port))
            flow_started_at = self.server_initiated_flows.get(flow_key)
            if flow_started_at is None:
                continue

            timestamp = _packet_time(packet, now)
            if timestamp < flow_started_at:
                continue

            self.server_initiated_flows[flow_key] = timestamp
            self.outbound_packets.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "packet_size": _non_negative_int(packet.get("packet_size")),
            })
            observed_keys.add((src_ip, dst_ip))

        return observed_keys

    def _build_volume_alerts(
        self,
        observed_keys: set[tuple[str, str]],
        now: datetime,
    ) -> list[dict[str, Any]]:
        cutoff = now - timedelta(seconds=self.volume_window_sec)
        alerts = []

        for key in observed_keys:
            src_ip, dst_ip = key
            packets = [
                packet
                for packet in self.outbound_packets
                if (
                    packet["src_ip"] == src_ip
                    and packet["dst_ip"] == dst_ip
                    and packet["timestamp"] >= cutoff
                )
            ]
            bit_count = sum(packet["packet_size"] * 8 for packet in packets)
            divisor = self.volume_window_sec if self.volume_window_sec > 0 else 1
            bps = bit_count / divisor

            history = self.volume_baselines.setdefault(
                key,
                deque(maxlen=self.outbound_baseline_samples),
            )
            baseline_bps = (
                float(median(history))
                if len(history) >= self.outbound_baseline_min_samples
                else 0.0
            )
            effective_threshold = max(
                self.outbound_bps_threshold,
                baseline_bps * self.outbound_baseline_multiplier,
            )

            if bps < effective_threshold:
                self.volume_alert_streaks[key] = 0
                history.append(bps)
                continue

            streak = self.volume_alert_streaks.get(key, 0) + 1
            self.volume_alert_streaks[key] = streak
            if streak < self.outbound_sustained_windows:
                continue

            alert_key = ("DATA_EXFILTRATION", f"{src_ip}->{dst_ip}")
            last_alert = self.last_alert_at.get(alert_key)
            if (
                last_alert is not None
                and (now - last_alert).total_seconds() < self.alert_cooldown_sec
            ):
                continue
            self.last_alert_at[alert_key] = now

            alerts.append({
                "attack_category": "EXFILTRATION",
                "attack_type": "DATA_EXFILTRATION",
                "severity": "high",
                "confidence": "medium",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "TCP",
                "detection_rule": "server_initiated_outbound_bps",
                "recommended_action": "alert",
                "response_level": "L2",
                "evidence": {
                    "matched_conditions": [
                        "protected_server_source",
                        "server_initiated_flow",
                        "outbound_bps_threshold_exceeded",
                        "sustained_window_threshold_satisfied",
                    ],
                    "window_seconds": self.volume_window_sec,
                    "packet_count": len(packets),
                    "bit_count": bit_count,
                    "bps": bps,
                    "absolute_bps_threshold": self.outbound_bps_threshold,
                    "baseline_bps": baseline_bps,
                    "baseline_multiplier": (
                        self.outbound_baseline_multiplier
                    ),
                    "effective_bps_threshold": effective_threshold,
                    "sustained_windows": streak,
                },
            })

        return alerts

    def _build_beacon_alerts(
        self,
        new_starts: list[dict[str, Any]],
        now: datetime,
    ) -> list[dict[str, Any]]:
        if not new_starts:
            return []

        cutoff = now - timedelta(seconds=self.beacon_window_sec)
        candidate_keys = {
            (event["src_ip"], event["dst_ip"], event["dst_port"])
            for event in new_starts
        }
        alerts = []

        for src_ip, dst_ip, dst_port in candidate_keys:
            events = [
                event
                for event in self.connection_starts
                if (
                    event["src_ip"] == src_ip
                    and event["dst_ip"] == dst_ip
                    and event["dst_port"] == dst_port
                    and event["timestamp"] >= cutoff
                )
            ]
            events.sort(key=lambda event: event["timestamp"])
            if len(events) < self.beacon_min_connections:
                continue

            sample = events[-self.beacon_min_connections:]
            intervals = [
                (
                    sample[index]["timestamp"]
                    - sample[index - 1]["timestamp"]
                ).total_seconds()
                for index in range(1, len(sample))
            ]
            median_interval = float(median(intervals))
            if (
                median_interval < self.beacon_min_interval_sec
                or median_interval > self.beacon_max_interval_sec
            ):
                continue

            max_deviation = max(
                abs(interval - median_interval)
                for interval in intervals
            )
            jitter_ratio = (
                max_deviation / median_interval
                if median_interval > 0
                else 1.0
            )
            if jitter_ratio > self.beacon_max_jitter_ratio:
                continue

            alert_key = (
                "C2_BEACON",
                f"{src_ip}->{dst_ip}:{dst_port}",
            )
            last_alert = self.last_alert_at.get(alert_key)
            if (
                last_alert is not None
                and (now - last_alert).total_seconds() < self.alert_cooldown_sec
            ):
                continue
            self.last_alert_at[alert_key] = now

            alerts.append({
                "attack_category": "COMMAND_AND_CONTROL",
                "attack_type": "C2_BEACON",
                "severity": "high",
                "confidence": "medium",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "TCP",
                "detection_rule": "periodic_server_egress",
                "recommended_action": "alert",
                "response_level": "L2",
                "evidence": {
                    "matched_conditions": [
                        "protected_server_source",
                        "server_initiated_flow",
                        "minimum_connection_count_satisfied",
                        "periodic_interval_range_satisfied",
                        "maximum_jitter_not_exceeded",
                    ],
                    "window_seconds": self.beacon_window_sec,
                    "connection_count": len(sample),
                    "minimum_connections": self.beacon_min_connections,
                    "dst_port": dst_port,
                    "intervals_seconds": intervals,
                    "median_interval_seconds": median_interval,
                    "jitter_ratio": jitter_ratio,
                    "maximum_jitter_ratio": self.beacon_max_jitter_ratio,
                },
            })

        return alerts

    def _expire_old_state(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.connection_retention_sec)
        while (
            self.connection_starts
            and self.connection_starts[0]["timestamp"] < cutoff
        ):
            self.connection_starts.popleft()

        self.last_flow_start = {
            key: timestamp
            for key, timestamp in self.last_flow_start.items()
            if timestamp >= cutoff
        }
        self.server_initiated_flows = {
            key: timestamp
            for key, timestamp in self.server_initiated_flows.items()
            if timestamp >= cutoff
        }
        active_pairs = {
            (key[0], key[1])
            for key in self.server_initiated_flows
        }
        self.volume_baselines = {
            key: history
            for key, history in self.volume_baselines.items()
            if key in active_pairs
        }
        self.volume_alert_streaks = {
            key: streak
            for key, streak in self.volume_alert_streaks.items()
            if key in active_pairs
        }
        self.last_alert_at = {
            key: timestamp
            for key, timestamp in self.last_alert_at.items()
            if timestamp >= cutoff
        }

        volume_cutoff = now - timedelta(seconds=self.volume_window_sec)
        while (
            self.outbound_packets
            and self.outbound_packets[0]["timestamp"] < volume_cutoff
        ):
            self.outbound_packets.popleft()


def _non_negative_int(value: Any) -> int:
    if not isinstance(value, (int, float)) or value < 0:
        return 0
    return int(value)
