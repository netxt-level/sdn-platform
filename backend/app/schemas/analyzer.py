from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


ALLOWED_PROTOCOL_STATS = {"TCP", "UDP", "ICMP", "ARP", "OTHER"}


class AnalyzerStatusRequest(BaseModel):
    """Analyzer가 Backend로 보내는 실행 상태와 런타임 안정성 지표."""

    timestamp: datetime
    analyzer_id: str = Field(min_length=1, max_length=30)
    status: Literal["running", "error"]
    interface: str = Field(min_length=1, max_length=30)
    capture_active: bool
    backend_connected: bool
    last_packet_at: Optional[datetime] = None
    last_summary_sent_at: Optional[datetime] = None
    error_message: Optional[str] = None
    pending_security_event_count: int = Field(default=0, ge=0)
    dropped_security_event_count: int = Field(default=0, ge=0)
    packet_buffer_dropped_count: int = Field(default=0, ge=0)
    last_security_event_send_failure: Optional[datetime] = None


class HostStat(BaseModel):
    src_host: Optional[str] = Field(default=None, max_length=255)
    src_ip: Optional[str] = None
    src_port: Optional[int] = Field(default=None, ge=1, le=65535)
    dst_host: Optional[str] = Field(default=None, max_length=255)
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: Literal["TCP", "UDP", "ICMP", "ARP", "OTHER"]
    packet_count: int = Field(ge=0)
    bit_count: int = Field(ge=0)


class PacketSummaryRequest(BaseModel):
    timestamp: datetime
    analyzer_id: str = Field(min_length=1, max_length=30)
    window_sec: float = Field(gt=0)
    total_packets: int = Field(ge=0)
    total_bits: int = Field(ge=0)
    protocol_stats: dict[str, int] = Field(max_length=50)
    host_stats: list[HostStat] = Field(max_length=100)

    @field_validator("protocol_stats")
    @classmethod
    def validate_protocol_stats(cls, value: dict[str, int]) -> dict[str, int]:
        if any(not protocol for protocol in value):
            raise ValueError("protocol_stats의 protocol 이름은 비어 있을 수 없습니다.")
        if any(len(protocol) > 10 for protocol in value):
            raise ValueError("protocol_stats의 protocol 이름이 너무 깁니다.")
        if any(protocol not in ALLOWED_PROTOCOL_STATS for protocol in value):
            raise ValueError("지원하지 않는 protocol_stats 이름입니다.")
        if any(count < 0 for count in value.values()):
            raise ValueError("protocol_stats의 패킷 수는 음수일 수 없습니다.")
        return value


class DetectionSummaryRequest(BaseModel):
    timestamp: datetime
    analyzer_id: str = Field(min_length=1, max_length=30)
    network_status: Literal["normal", "warning", "critical"]
    total_bps: float = Field(ge=0)
    total_pps: float = Field(ge=0)
    active_flow_count: int = Field(ge=0)
