from datetime import datetime, timezone
from typing import Any


# 패킷 요약 정보를 기반으로 네트워크 트래픽 상태를 계산하는 클래스
class TrafficStatsBuilder:
    def __init__(
        self,
        analyzer_id: str = "analyzer-1",
        suspicious_pps_threshold: float = 1000,
        suspicious_bps_threshold: float = 5_000_000,
        critical_pps_threshold: float = 3000,
        critical_bps_threshold: float = 10_000_000,
    ):
        self.analyzer_id = analyzer_id                              # 분석 서버 ID
        self.suspicious_pps_threshold = suspicious_pps_threshold    # 의심 호스트 판단 초당 패킷 수
        self.suspicious_bps_threshold = suspicious_bps_threshold    # 의심 호스트 판단 초당 비트 수
        self.critical_pps_threshold = critical_pps_threshold        # critical 판단 초당 패킷 수
        self.critical_bps_threshold = critical_bps_threshold        # critical 판단 초당 비트 수

    # 패킷 요약 정보와 원본 패킷 목록을 기반으로 트래픽 통계 생성
    def build_traffic_stats(
        self,
        packet_summary: dict[str, Any],
        packets: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:

        window_sec = packet_summary.get("window_sec", 1)        # 패킷 집계 시간 범위
        total_packets = packet_summary.get("total_packets", 0)  # 전체 패킷 수
        total_bits = packet_summary.get("total_bits", 0)        # 전체 비트 수

        # 전체 초당 패킷 수 계산
        total_pps = total_packets

        # 전체 초당 비트 수 계산
        total_bps = total_bits

        # 의심 호스트 목록 생성
        suspicious_hosts = self._build_suspicious_hosts(
            host_stats=packet_summary.get("host_stats", []),
            window_sec=window_sec,
        )

        # 의심 호스트 개수 계산
        suspicious_host_count = len(suspicious_hosts)

        # 현재 활성화된 플로우 개수 계산
        active_flow_count = self._count_active_flows(packets)

        # 전체 트래픽 상태 판단
        network_status = self._decide_network_status(
            total_bps=total_bps,
            total_pps=total_pps,
            suspicious_host_count=suspicious_host_count,
        )

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),        # 통계 생성 시각
            "analyzer_id": self.analyzer_id,                            # 분석 서버 ID
            "network_status": network_status,                           # 네트워크 상태
            "total_bps": total_bps,                                     # 전체 초당 비트 수
            "total_pps": total_pps,                                     # 전체 초당 패킷 수
            "active_flow_count": active_flow_count,                     # 활성 플로우 개수
            "suspicious_host_count": suspicious_host_count,             # 의심 호스트 개수
            "suspicious_hosts": suspicious_hosts,                       # 의심 호스트 목록
        }

    # 의심 호스트 목록을 생성하는 내부 함수
    def _build_suspicious_hosts(
        self,
        host_stats: list[dict[str, Any]],
        window_sec: int,
    ) -> list[dict[str, Any]]:
        suspicious_hosts = []

        for host in host_stats:
            packet_count = host.get("packet_count", 0)  # 호스트별 패킷 수
            bit_count = host.get("bit_count", 0)        # 호스트별 비트 수

            # 호스트별 초당 패킷 수 계산
            pps = packet_count / window_sec if window_sec > 0 else 0

            # 호스트별 초당 비트 수 계산
            bps = bit_count / window_sec if window_sec > 0 else 0

            # 의심 호스트 판단 사유 목록
            reasons = []

            # 초당 패킷 수가 임계값 이상이면 의심 사유 추가
            if pps >= self.suspicious_pps_threshold:
                reasons.append("pps threshold exceeded")

            # 초당 비트 수가 임계값 이상이면 의심 사유 추가
            if bps >= self.suspicious_bps_threshold:
                reasons.append("bps threshold exceeded")

            # 의심 사유가 없으면 의심 호스트 목록에 포함하지 않음
            if not reasons:
                continue

            suspicious_hosts.append({
                "host": host.get("src_host") or host.get("src_ip"),     # 출발지 호스트 이름 또는 IP
                "ip": host.get("src_ip"),                               # 출발지 IP
                "protocol": host.get("protocol"),                       # 프로토콜
                "bps": bps,                                             # 호스트별 초당 비트 수
                "pps": pps,                                             # 호스트별 초당 패킷 수
                "reasons": reasons,                                     # 의심 판단 사유
            })

        # 초당 비트 수가 높은 순서로 정렬
        suspicious_hosts.sort(
            key=lambda item: item["bps"],
            reverse=True,
        )

        return suspicious_hosts

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

            # 출발지 IP, 목적지 IP, 프로토콜이 있는 패킷만 플로우로 계산
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
