from datetime import datetime, timezone
from typing import Any

# 패킷 요약 정보를 기반으로 네트워크 트래픽 상태를 계산하는 클래스
class TrafficStatsBuilder:
    def __init__(
        self,
        analyzer_id: str = "analyzer-1",
        top_talker_limit: int = 5,
        suspicious_pps_threshold: float = 1000,
        suspicious_bps_threshold: float = 5_000_000,
        critical_pps_threshold: float = 3000,
        critical_bps_threshold: float = 10_000_000,
    ):
        self.analyzer_id = analyzer_id                              # 패킷 전송 스위치 ID
        self.top_talker_limit = top_talker_limit                    # top_talker 호스트 출력 개수
        self.suspicious_pps_threshold = suspicious_pps_threshold    # 의심 호스트 판단 패킷 수
        self.suspicious_bps_threshold = suspicious_bps_threshold    # 의심 호스트 판단 비트 수
        self.critical_pps_threshold = critical_pps_threshold        # critical 판단 초당 패킷 수
        self.critical_bps_threshold = critical_bps_threshold        # critical 판단 초당 비트 수

    # 패킷 요약 정보와 원본 패킷 목록을 기반으로 트래픽 통계 생성
    def build_traffic_stats(
        self,
        packet_summary: dict[str, Any],
        packets: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        
        total_packets = packet_summary.get("total_packets", 0)  # 전체 패킷 수
        total_bps = packet_summary.get("bps", 0)                # 전체 초당 비트 수
        total_pps = packet_summary.get("pps", 0)                # 전체 초당 패킷 수

        # 프로토콜 별 비율 계산
        protocol_distribution = self._build_protocol_distribution(
            protocol_stats=packet_summary.get("protocol_stats", {}),
            total_packets=total_packets,
        )

        # 트래픽 양이 많은 호스트 목록 생성
        top_talkers = self._build_top_talkers(
            host_stats=packet_summary.get("host_stats", [])
        )

        # top_talker 중 suspicous(의심) 상태의 호스트 개수 계산
        suspicious_host_count = sum(
            1
            for talker in top_talkers
            if talker["status"] == "suspicious"
        )

        # 현재 활성화된 플로우 개수 계산
        active_flow_count = self._count_active_flows(packets)

        # 전체 트래픽 상태 판단
        network_status = self._decide_network_status(
            total_bps=total_bps,
            total_pps=total_pps,
            suspicious_host_count=suspicious_host_count,
        )

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),    # 통계 생성 시각
            "analyzer_id": self.analyzer_id,                        # 패킷 전송 스위치 ID
            "network_status": network_status,                       # 네트워크 상태 (normal, warning, critical)
            "active_flow_count": active_flow_count,                 # 활성 플로우 개수
            "suspicious_host_count": suspicious_host_count,         # 의심 호스트 개수
            "top_talkers": top_talkers,                             # 트래픽이 많은 호스트 목록
        }

    # 프로토콜별 패킷 비율을 계산하는 내부 함수     -> ARP, SYN 등 추후 더 세부적으로 나눠야함
    def _build_protocol_distribution(
        self,
        protocol_stats: dict[str, int],
        total_packets: int,
    ) -> dict[str, float]:
        if total_packets <= 0:
            return {}

        return {
            protocol: round((count / total_packets) * 100, 1)
            for protocol, count in protocol_stats.items()
        }

    # 트래픽 사용량이 많은 호스트 목록을 생성하는 내부 함수
    def _build_top_talkers(
        self,
        host_stats: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        talkers = []

        # 호스트 통계 확인
        for host in host_stats:
            bps = host.get("bps", 0)
            pps = host.get("pps", 0)

            status = "normal"

            # pps 또는 bps가 임계값 이상일 경우 의심 패킷으로 판단
            if (
                pps >= self.suspicious_pps_threshold
                or bps >= self.suspicious_bps_threshold
            ):
                status = "suspicious"

            # 호스트 트래픽 정보 저장
            talkers.append({
                "host": host.get("src_host") or host.get("src_ip"),
                "ip": host.get("src_ip"),
                "bps": bps,
                "pps": pps,
                "status": status,
            })

        # bps 순서 정렬
        talkers.sort(
            key=lambda item: item["bps"],
            reverse=True,
        )

        # 설정된 개수만큼 상위 호스트 반환
        return talkers[:self.top_talker_limit]

    # 현재 활성화된 플로우 개수를 계산하는 내부 함수
    def _count_active_flows(
        self,
        packets: list[dict[str, Any]] | None,
    ) -> int:
        if not packets:
            return 0

        flow_keys = set()

        for packet in packets:
            flow_key = (
                packet.get("src_ip"),
                packet.get("dst_ip"),
                packet.get("protocol"),
                packet.get("src_port"),
                packet.get("dst_port"),
            )

            if flow_key[0] and flow_key[1] and flow_key[2]:
                flow_keys.add(flow_key)

        return len(flow_keys)

    # 전체 네트워크 상태를 판단하는 내부 함수
    def _decide_network_status(
        self,
        total_bps: float,
        total_pps: float,
        suspicious_host_count: int,
    ) -> str:
        
        # 전체 bps 또는 pps가 critical 기준 이상일 경우 심각 상태
        if (
            total_bps >= self.critical_bps_threshold
            or total_pps >= self.critical_pps_threshold
        ):
            return "critical"

        # 의심 호스트가 하나라도 존재할 경우 경고 상태
        if suspicious_host_count > 0:
            return "warning"

        # 위 조건에 해당하지 않으면 정상 상태
        return "normal"
