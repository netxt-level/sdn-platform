from datetime import datetime
from typing import Optional
from pydantic import BaseModel

class AnalyzerStatusRequest(BaseModel):                 # 분석 서버 상태 요청 모델
    timestamp: datetime                                 # 상태 보고 시각
    analyzer_id: str                                    # 분석 서버 ID
    status: str                                         # 분석 서버 상태
    interface: str                                      # 캡처 네트워크 인터페이스
    capture_active: bool                                # 패킷 캡처 활성 여부
    backend_connected: bool                             # 백엔드 연결 여부
    last_packet_at: Optional[datetime] = None           # 마지막 패킷 수신 시각
    last_summary_sent_at: Optional[datetime] = None     # 마지막 요약 전송 시각
    error_message: Optional[str] = None                 # 오류 메시지

class HostStat(BaseModel):                              # 호스트/프로토콜별 통계 모델
    src_host: Optional[str] = None                      # 출발지 호스트명
    src_ip: Optional[str] = None                        # 출발지 IP
    src_port: Optional[int] = None                      # 출발지 포트
    dst_host: Optional[str] = None                      # 목적지 호스트명
    dst_ip: Optional[str] = None                        # 목적지 IP
    dst_port: Optional[int] = None                      # 목적지 포트
    protocol: str                                       # 프로토콜
    packet_count: int                                   # 패킷 수
    bit_count: int                                      # 비트 수

class PacketSummaryRequest(BaseModel):                  # 패킷 요약 요청 모델
    timestamp: datetime                                 # 요약 생성 시각
    analyzer_id: str                                    # 분석 서버 ID
    window_sec: int                                     # 집계 시간(초)
    total_packets: int                                  # 전체 패킷 수
    total_bits: int                                     # 전체 비트 수
    protocol_stats: dict[str, int]                      # 프로토콜별 패킷 수
    host_stats: list[HostStat]                          # 호스트별 통계 목록

class DetectionSummaryRequest(BaseModel):               # 트래픽 상태 요약 요청 모델
    timestamp: datetime                                 # 트래픽 상태 요약 생성 시각
    analyzer_id: str                                    # 분석 서버 ID
    network_status: str                                 # 네트워크 상태
    total_bps: float                                    # 전체 초당 비트 수
    total_pps: float                                    # 전체 초당 패킷 수
    active_flow_count: int                              # 활성 flow 수
