from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

# 일정 시간 단위로 수집된 패킷 목록을 요약 정보로 변환
class PacketSummaryBuilder:
    def __init__(self, analyzer_id: str = "analyzer-1", window_sec: int = 1):
        self.analyzer_id = analyzer_id  # 패킷 전송 스위치 구분 ID
        self.window_sec = window_sec    # 패킷 집계 시간 (초 단위)
        
    # 패킷 메타데이터 목록을 받아 전체 요약 정보를 생성하는 함수
    def build_packet_summary(self, packets: list[dict[str, Any]]) -> dict[str, Any]:
        
        # 전체 패킷 개수 계산
        total_packets = len(packets)
        
        # 전체 바이트 수 계산 (기본값 0)
        total_bytes = sum(
            packet.get("packet_size", 0)
            for packet in packets
        )
        
        # 프로토콜 별 패킷 개수 집계
        # protocol 값이 없을 경우 UNKNOWN 처리
        protocol_stats = Counter(
            packet.get("protocol", "UNKNOWN")
            for packet in packets
        )
        
        # 출발지, 목적지, 프로토콜 기준으로 호스트별 통계 생성
        host_stats = self._build_host_stats(packets)
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),    # 현재 시간
            "analyzer_id": self.analyzer_id,                        # 스위치 ID
            "window_sec": self.window_sec,                          # 집계 시간
            "total_packets": total_packets,                         # 전체 패킷 수
            "total_bytes": total_bytes,                             # 전체 바이트 수
            "pps": self._calculate_pps(total_packets),              # 초당 패킷 수
            "bps": self._calculate_bps(total_bytes),                # 초당 비트 수
            "protocol_stats": dict(protocol_stats),                 # 프로토콜 별 패킷 개수
            "host_stats": host_stats,                               # 호스트 간 통신 통계
        }
    
    # 호스트 간 통신 정보를 기준으로 패킷 통계를 생성하는 내부 함수
    def _build_host_stats(self, packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        host_map = defaultdict(lambda: {
            "src_host": None,
            "src_ip": None,
            "dst_host": None,
            "dst_ip": None,
            "packet_count": 0,
            "byte_count": 0,
        })
        
        # 패킷 통계 누적
        for packet in packets:
            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            protocol = packet.get("protocol", "UNKNOWN")
            
            if not src_ip or not dst_ip:
                continue
            
            key = (
                packet.get("src_host"),
                src_ip,
                packet.get("dst_host"),
                dst_ip,
                protocol,
            )
            
            # 그룹에 해당하는 통계 정보 저장 및 갱신
            host_map[key]["src_host"] = packet.get("src_host")
            host_map[key]["src_ip"] = src_ip
            host_map[key]["dst_host"] = packet.get("dst_host")
            host_map[key]["dst_ip"] = dst_ip
            host_map[key]["protocol"] = protocol
            
            # 패킷 수 누적
            host_map[key]["packet_count"] += 1
            
            # 바이트 수 누적
            host_map[key]["byte_count"] += packet.get("packet_size", 0)
        
        # 최종 호스트 통계 목록    
        host_stats = []
        
        for values in host_map.values():
            packet_count = values["packet_count"]
            byte_count = values["byte_count"]
            
            host_stats.append({
                "src_host": values["src_host"],             # 출발지 Host
                "src_ip": values["src_ip"],                 # 출발지 IP
                "dst_host": values["dst_host"],             # 목적지 Host
                "dst_ip": values["dst_ip"],                 # 목적지 IP
                "protocol": values["protocol"],             # 프로토콜
                "packet_count": packet_count,               # 해당 통신의 패킷 수
                "byte_count": byte_count,                   # 해당 통신의 전체 바이트 수
                "pps": self._calculate_pps(packet_count),   # 해당 통신의 초당 패킷 수
                "bps": self._calculate_bps(byte_count),     # 해당 통신의 초당 비트 수
            })
        
        # 수집된 통신 흐름을 bps 순으로 정렬
        host_stats.sort(
            key=lambda item: item["bps"],
            reverse=True,
        )
        
        return host_stats
    
    # 초당 패킷 수 계산
    def _calculate_pps(self, packet_count: int) -> float:
        if self.window_sec <= 0:
            return 0
    
        return round(packet_count / self.window_sec, 3)
    
    # 초당 비트 수 계산
    def _calculate_bps(self, byte_count: int) -> float:
        if self.window_sec <= 0:
            return 0

        # byte를 bit로 변환하여 bps 계산
        return round((byte_count * 8) / self.window_sec, 3)