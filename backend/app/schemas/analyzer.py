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
    dst_host: Optional[str] = None                      # 목적지 호스트명
    dst_ip: Optional[str] = None                        # 목적지 IP
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

class SuspiciousHost(BaseModel):                        # 의심 호스트 모델
    host: Optional[str] = None                          # 호스트명
    ip: str                                             # IP 주소
    protocol: str                                       # 프로토콜
    bps: float                                          # 초당 비트 수
    pps: float                                          # 초당 패킷 수
    reasons: list[str]                                  # 의심 판단 이유
    attack_type: Optional[str] = None                   # 공격/이상 트래픽 유형

class DetectionSummaryRequest(BaseModel):               # 탐지 요약 요청 모델
    timestamp: datetime                                 # 탐지 요약 생성 시각
    analyzer_id: str                                    # 분석 서버 ID
    network_status: str                                 # 네트워크 상태
    total_bps: float                                    # 전체 초당 비트 수
    total_pps: float                                    # 전체 초당 패킷 수
    active_flow_count: int                              # 활성 flow 수
    suspicious_host_count: int                          # 의심 호스트 수
    suspicious_hosts: list[SuspiciousHost]              # 의심 호스트 목록
