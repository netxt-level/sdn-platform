from collections import defaultdict, deque
from datetime import datetime, timedelta


# TCP SYN 패킷이 짧은 시간 안에 여러 목적지 포트로 향하는지 확인해
# 단순 포트 스캔 의심 호스트를 찾아내는 탐지기
class PortScanDetector:
    def __init__(
        self,
        window_sec=5,
        unique_port_threshold=20,
        syn_count_threshold=20,
        multi_target_window_sec=30,
        multi_target_threshold=3,
        high_unique_dst_port_threshold=50,
        alert_cooldown_sec=60,
    ):
        # 최근 window_sec초 안에 관측된 SYN 이벤트만 탐지 기준으로 사용
        self.window_sec = window_sec
        # 동일 출발지/목적지 조합에서 서로 다른 목적지 포트가 이 값 이상이면 의심으로 판단
        self.unique_port_threshold = unique_port_threshold
        self.syn_count_threshold = syn_count_threshold
        self.multi_target_window_sec = multi_target_window_sec
        self.multi_target_threshold = multi_target_threshold
        self.high_unique_dst_port_threshold = high_unique_dst_port_threshold
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
            packet_size = packet.get("packet_size", 0)

            if not src_ip or not dst_ip or dst_port is None:
                continue
            if not isinstance(packet_size, (int, float)) or packet_size < 0:
                packet_size = 0

            # 이후 윈도우 집계를 위해 필요한 최소 정보만 저장한다.
            self.events.append({
                "timestamp": now,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "packet_size": int(packet_size),
            })

        # 탐지 윈도우 밖의 오래된 이벤트는 제거한다.
        self._expire_old_events(now)

        window_cutoff = now - timedelta(seconds=self.window_sec)
        multi_target_cutoff = now - timedelta(seconds=self.multi_target_window_sec)
        grouped = defaultdict(
            lambda: {
                "ports": set(),
                "syn_count": 0,
                "bit_count": 0,
            }
        )
        multi_target_grouped = defaultdict(set)

        # 출발지/목적지 쌍마다 접근한 목적지 포트 종류를 모은다.
        for event in self.events:
            if event["timestamp"] >= window_cutoff:
                key = (event["src_ip"], event["dst_ip"])
                grouped[key]["ports"].add(event["dst_port"])
                grouped[key]["syn_count"] += 1
                grouped[key]["bit_count"] += event["packet_size"] * 8

            if event["timestamp"] >= multi_target_cutoff:
                key = (event["src_ip"], event["dst_ip"])
                multi_target_grouped[key].add(event["dst_port"])

        scanned_targets_by_source = defaultdict(set)
        for (src_ip, dst_ip), ports in multi_target_grouped.items():
            if len(ports) >= self.unique_port_threshold:
                scanned_targets_by_source[src_ip].add(dst_ip)

        for (src_ip, dst_ip), stats in grouped.items():
            ports = stats["ports"]
            syn_count = stats["syn_count"]
            bit_count = stats["bit_count"]

            # 고유 목적지 포트 수가 임계값보다 작으면 정상 연결 시도로 간주한다.
            if len(ports) < self.unique_port_threshold:
                continue

            matched_conditions = [
                "tcp_syn_without_ack",
                "same_source_target_pair",
                "unique_dst_port_threshold_exceeded",
            ]
            score = 60

            if syn_count >= self.syn_count_threshold:
                matched_conditions.append("syn_count_threshold_satisfied")
                score += 10

            if (
                len(scanned_targets_by_source[src_ip])
                >= self.multi_target_threshold
            ):
                matched_conditions.append("multi_target_scan")
                score += 15

            if len(ports) >= self.high_unique_dst_port_threshold:
                matched_conditions.append("high_unique_dst_port_count")
                score += 15

            score = min(score, 100)
            has_auxiliary_condition = len(matched_conditions) > 3
            response_level = "L2" if has_auxiliary_condition else "L1"
            recommended_action = "alert" if has_auxiliary_condition else "monitor"
            rate_window = self.window_sec if self.window_sec > 0 else 1

            alert_key = (src_ip, dst_ip)
            last_alert = self.last_alert_at.get(alert_key)

            # 같은 스캔 패턴을 매 윈도우마다 중복 보고하지 않도록 cooldown을 적용한다.
            if last_alert and (now - last_alert).total_seconds() < self.alert_cooldown_sec:
                continue

            self.last_alert_at[alert_key] = now

            # SecurityEventBuilder가 공통 보안 이벤트로 변환할 수 있는 형태로 반환한다.
            detected.append({
                "host": src_ip,
                "ip": src_ip,
                "protocol": "TCP",
                "bps": bit_count / rate_window,
                "pps": syn_count / rate_window,
                "attack_type": "PORT_SCAN",
                "reasons": [
                    "Port Scan",
                ],
                "target_ip": dst_ip,
                "window_seconds": self.window_sec,
                "packet_count": syn_count,
                "bit_count": bit_count,
                "unique_dst_port_count": len(ports),
                "unique_dst_ports": sorted(ports),
                "syn_count": syn_count,
                "matched_conditions": matched_conditions,
                "score": score,
                "response_level": response_level,
                "recommended_action": recommended_action,
            })

        return detected

    def _expire_old_events(self, now):
        retention_sec = max(self.window_sec, self.multi_target_window_sec)
        cutoff = now - timedelta(seconds=retention_sec)

        # deque는 시간 순서대로 쌓이므로 앞에서부터 만료된 이벤트를 제거한다.
        while self.events and self.events[0]["timestamp"] < cutoff:
            self.events.popleft()
