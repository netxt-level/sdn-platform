from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any


ALLOWED_PROTOCOLS = {"TCP", "UDP", "ICMP", "ARP", "OTHER"}


# 일정 시간 동안 수집한 패킷 정보를 요약하는 클래스
class PacketSummaryBuilder:
    def __init__(
        self,
        analyzer_id: str = "analyzer-1",
        window_sec: int = 1,
        max_host_stats: int = 50,
    ):
        self.analyzer_id = analyzer_id      # 분석 서버 ID
        self.window_sec = window_sec        # 패킷 집계 시간 범위
        self.max_host_stats = max_host_stats

    # 패킷 목록을 기반으로 패킷 요약 정보 생성
    def build_packet_summary(
        self,
        packets: list[dict[str, Any]],
        window_sec: int | float | None = None,
    ) -> dict[str, Any]:
        effective_window_sec = (
            float(window_sec)
            if window_sec is not None and window_sec > 0
            else float(self.window_sec)
        )

        # 프로토콜별 패킷 수 계산
        total_packets = len(packets)

        # 프로토콜별 비트 수 계산
        total_bits = sum(
            packet.get("packet_size", 0) * 8
            for packet in packets
        )

        protocol_stats = Counter(
            _normalize_protocol(packet.get("protocol"))
            for packet in packets
        )

        # 호스트 쌍 및 프로토콜별 패킷 요약 생성
        host_stats = self._build_host_stats(packets)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),    # 요약 생성 시각
            "analyzer_id": self.analyzer_id,                        # 분석 서버 ID
            "window_sec": effective_window_sec,                     # 실제 집계 시간 범위
            "total_packets": total_packets,                         # 전체 패킷 수
            "total_bits": total_bits,                               # 전체 비트 수
            "protocol_stats": dict(protocol_stats),                 # 프로토콜별 패킷 수
            "host_stats": host_stats,                               # 호스트별 패킷 요약
        }

    # 호스트 쌍과 프로토콜별 패킷 수 및 비트 수를 계산하는 내부 함수
    def _build_host_stats(
        self,
        packets: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        host_map = defaultdict(lambda: {
            "src_host": None,
            "src_ip": None,
            "src_port": None,
            "dst_host": None,
            "dst_ip": None,
            "dst_port": None,
            "protocol": None,
            "packet_count": 0,
            "bit_count": 0,
        })

        for packet in packets:
            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            protocol = _normalize_protocol(packet.get("protocol"))

            # 출발지 IP 또는 목적지 IP가 없으면 호스트 통계에서 제외
            if not src_ip or not dst_ip:
                continue

            key = (
                packet.get("src_host"),
                src_ip,
                packet.get("dst_host"),
                dst_ip,
                protocol,
            )

            packet_bits = packet.get("packet_size", 0) * 8

            host_map[key]["src_host"] = packet.get("src_host")
            host_map[key]["src_ip"] = src_ip
            host_map[key]["dst_host"] = packet.get("dst_host")
            host_map[key]["dst_ip"] = dst_ip
            host_map[key]["protocol"] = protocol
            host_map[key]["packet_count"] += 1
            host_map[key]["bit_count"] += packet_bits

        host_stats = list(host_map.values())

        # 비트 수가 높은 순서로 정렬
        host_stats.sort(
            key=lambda item: item.get("bit_count", 0),
            reverse=True,
        )

        return host_stats[:self.max_host_stats]


def _normalize_protocol(protocol: Any) -> str:
    protocol_name = str(protocol or "OTHER").upper()
    if protocol_name in ALLOWED_PROTOCOLS:
        return protocol_name
    return "OTHER"
