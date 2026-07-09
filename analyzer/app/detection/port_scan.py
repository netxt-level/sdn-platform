from collections import defaultdict, deque
from datetime import datetime, timedelta


# 일반적으로 스캔 대상이 되기 쉬운 관리/서비스 포트다.
# 이 포트들이 함께 나타나면 단순 접속보다 점검 또는 스캔 가능성이 높다고 본다.
COMMON_SCAN_PORTS = {
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    6379,
    8080,
}


class PortScanDetector:
    """TCP SYN 패턴을 모아 포트 스캔 의심 흐름을 찾는다."""

    def __init__(
        self,
        window_sec=5,
        unique_port_threshold=10,
        syn_count_threshold=10,
        multi_target_window_sec=30,
        multi_target_threshold=2,
        high_unique_dst_port_threshold=25,
        common_port_hit_threshold=3,
        alert_cooldown_sec=30,
    ):
        # 짧은 시간 안에 여러 포트로 연결을 시도하는지를 보기 위한 기본 창이다.
        self.window_sec = window_sec
        # 같은 출발지와 목적지 사이에서 서로 다른 목적지 포트가 이 값 이상이면 탐지한다.
        self.unique_port_threshold = unique_port_threshold
        # 포트 종류뿐 아니라 SYN 시도 자체가 반복됐는지도 같이 본다.
        self.syn_count_threshold = syn_count_threshold
        # 한 호스트가 여러 대상 IP를 스캔하는지 확인하기 위한 보조 창이다.
        self.multi_target_window_sec = multi_target_window_sec
        self.multi_target_threshold = multi_target_threshold
        # 이 값 이상이면 포트 수가 매우 많은 스캔으로 보고 점수를 더한다.
        self.high_unique_dst_port_threshold = high_unique_dst_port_threshold
        # 자주 노리는 포트가 여러 개 포함되면 보조 근거로 사용한다.
        self.common_port_hit_threshold = common_port_hit_threshold
        # 같은 흐름이 매 창마다 반복 보고되지 않도록 잠깐 묶어 둔다.
        self.alert_cooldown_sec = alert_cooldown_sec

        self.events = deque()
        self.last_alert_at = {}

    def detect(self, packets):
        now = datetime.now()

        for packet in packets:
            if packet.get("protocol") != "TCP":
                continue

            # SYN만 있고 ACK가 없는 패킷을 연결 시도 패턴으로 본다.
            flags = str(packet.get("tcp_flags", "")).upper()
            if "S" not in flags or "A" in flags:
                continue

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            dst_port = self._to_int(packet.get("dst_port"))
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

    def _build_alerts(self, now):
        window_cutoff = now - timedelta(seconds=self.window_sec)
        multi_target_cutoff = now - timedelta(seconds=self.multi_target_window_sec)
        grouped = defaultdict(lambda: {"ports": set(), "syn_count": 0})
        scan_targets_by_source = defaultdict(set)

        for event in self.events:
            src_ip = event["src_ip"]
            dst_ip = event["dst_ip"]

            if event["timestamp"] >= window_cutoff:
                grouped[(src_ip, dst_ip)]["ports"].add(event["dst_port"])
                grouped[(src_ip, dst_ip)]["syn_count"] += 1

            if event["timestamp"] >= multi_target_cutoff:
                scan_targets_by_source[src_ip].add(dst_ip)

        alerts = []
        for (src_ip, dst_ip), stats in grouped.items():
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
                self._make_alert(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ports=ports,
                    syn_count=syn_count,
                    scanned_target_count=len(scan_targets_by_source[src_ip]),
                )
            )

        return alerts

    def _make_alert(self, src_ip, dst_ip, ports, syn_count, scanned_target_count):
        common_ports = sorted(port for port in ports if port in COMMON_SCAN_PORTS)
        matched_conditions = [
            "TCP SYN만 있고 ACK는 없음",
            "출발지와 목적지 IP가 확인됨",
            "고유 목적지 포트 수 기준 초과",
        ]
        score = 50

        if syn_count >= self.syn_count_threshold:
            matched_conditions.append("SYN 시도 수 기준 초과")
            score += 10

        if scanned_target_count >= self.multi_target_threshold:
            matched_conditions.append("여러 대상 IP로 스캔 시도")
            score += 15

        if len(common_ports) >= self.common_port_hit_threshold:
            matched_conditions.append("관리/서비스 포트 다수 포함")
            score += 10

        if len(ports) >= self.high_unique_dst_port_threshold:
            matched_conditions.append("고유 목적지 포트 수가 높은 기준 초과")
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
            "common_dst_ports": common_ports,
            "syn_count": syn_count,
            "scanned_target_count": scanned_target_count,
            "matched_conditions": matched_conditions,
            "score": score,
            "response_level": response_level,
            "recommended_action": recommended_action,
        }

    def _expire_old_events(self, now):
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

    def _to_int(self, value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
