from collections import defaultdict, deque
from datetime import datetime, timedelta


class PortScanDetector:
    def __init__(self, window_sec=5, unique_port_threshold=20, alert_cooldown_sec=30):
        self.window_sec = window_sec
        self.unique_port_threshold = unique_port_threshold
        self.alert_cooldown_sec = alert_cooldown_sec

        self.events = deque()
        self.last_alert_at = {}

    def detect(self, packets):
        now = datetime.now()
        detected = []

        for packet in packets:
            if packet.get("protocol") != "TCP":
                continue

            flags = packet.get("tcp_flags", "")
            if "S" not in flags or "A" in flags:
                continue

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            dst_port = packet.get("dst_port")

            if not src_ip or not dst_ip or dst_port is None:
                continue

            self.events.append({
                "timestamp": now,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            })

        self._expire_old_events(now)

        grouped = defaultdict(set)

        for event in self.events:
            key = (event["src_ip"], event["dst_ip"])
            grouped[key].add(event["dst_port"])

        for (src_ip, dst_ip), ports in grouped.items():
            if len(ports) < self.unique_port_threshold:
                continue

            alert_key = (src_ip, dst_ip)
            last_alert = self.last_alert_at.get(alert_key)

            if last_alert and (now - last_alert).total_seconds() < self.alert_cooldown_sec:
                continue

            self.last_alert_at[alert_key] = now

            detected.append({
                "host": src_ip,
                "ip": src_ip,
                "protocol": "TCP",
                "bps": 0,
                "pps": 0,
                "attack_type": "PORT_SCAN",
                "reasons": [
                    "Port Scan",
                ],
                "target_ip": dst_ip,
                "unique_dst_port_count": len(ports),
            })

        return detected

    def _expire_old_events(self, now):
        cutoff = now - timedelta(seconds=self.window_sec)

        while self.events and self.events[0]["timestamp"] < cutoff:
            self.events.popleft()
