from collections import defaultdict, deque
from datetime import datetime, timedelta


# TCP SYN 패킷이 짧은 시간 안에 여러 목적지 포트로 향하는지 확인해
# 단순 포트 스캔 의심 호스트를 찾아내는 탐지기
class PortScanDetector:
    def __init__(self, window_sec=5, unique_port_threshold=20, alert_cooldown_sec=30):
        # 최근 window_sec초 안에 관측된 SYN 이벤트만 탐지 기준으로 사용
        self.window_sec = window_sec
        # 동일 출발지/목적지 조합에서 서로 다른 목적지 포트가 이 값 이상이면 의심으로 판단
        self.unique_port_threshold = unique_port_threshold
        # 같은 출발지/목적지 조합에 대해 알림이 반복 생성되는 것을 막는 최소 간격
        self.alert_cooldown_sec = alert_cooldown_sec

        # 최근 SYN 이벤트를 시간 순서대로 보관해 오래된 이벤트를 빠르게 제거
        self.events = deque()
        # alert_key(src_ip, dst_ip)별 마지막 탐지 시각
        self.last_alert_at = {}

    def detect(self, packets):
        now = datetime.now()
        detected = []

        for packet in packets:
            # 포트 스캔 탐지는 TCP 패킷만 대상으로 한다.
            if packet.get("protocol") != "TCP":
                continue

            # SYN은 있고 ACK는 없는 패킷을 연결 시도 패턴으로 본다.
            flags = packet.get("tcp_flags", "")
            if "S" not in flags or "A" in flags:
                continue

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            dst_port = packet.get("dst_port")

            if not src_ip or not dst_ip or dst_port is None:
                continue

            # 이후 윈도우 집계를 위해 필요한 최소 정보만 저장한다.
            self.events.append({
                "timestamp": now,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            })

        # 탐지 윈도우 밖의 오래된 이벤트는 제거한다.
        self._expire_old_events(now)

        grouped = defaultdict(set)

        # 출발지/목적지 쌍마다 접근한 목적지 포트 종류를 모은다.
        for event in self.events:
            key = (event["src_ip"], event["dst_ip"])
            grouped[key].add(event["dst_port"])

        for (src_ip, dst_ip), ports in grouped.items():
            # 고유 목적지 포트 수가 임계값보다 작으면 정상 연결 시도로 간주한다.
            if len(ports) < self.unique_port_threshold:
                continue

            alert_key = (src_ip, dst_ip)
            last_alert = self.last_alert_at.get(alert_key)

            # 같은 스캔 패턴을 매 윈도우마다 중복 보고하지 않도록 cooldown을 적용한다.
            if last_alert and (now - last_alert).total_seconds() < self.alert_cooldown_sec:
                continue

            self.last_alert_at[alert_key] = now

            # TrafficStatsBuilder가 suspicious_hosts에 합칠 수 있는 형태로 반환한다.
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

        # deque는 시간 순서대로 쌓이므로 앞에서부터 만료된 이벤트를 제거한다.
        while self.events and self.events[0]["timestamp"] < cutoff:
            self.events.popleft()
