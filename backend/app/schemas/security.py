from datetime import datetime
from ipaddress import IPv4Address
from typing import Any
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.schemas.flow import FlowMitigation


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    event_fingerprint: str
    dedup_key: str
    timestamp: datetime
    analyzer_id: str
    attack_category: Literal["FLOOD", "RECON"]
    attack_type: Literal["PORT_SCAN", "ICMP_FLOOD", "UDP_FLOOD", "SYN_FLOOD"]
    severity: Literal["low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    status: Literal["detected", "mitigating", "resolved", "failed"]
    src_ip: IPv4Address
    dst_ip: IPv4Address
    protocol: Literal["ICMP", "UDP", "TCP"]
    detection_rule: str
    recommended_action: Literal["log", "alert", "rate_limit", "drop"]
    response_level: Literal["L0", "L1", "L2", "L3"]
    evidence: dict[str, Any]
    mitigation: FlowMitigation | None = None


class SecurityEventsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    analyzer_id: str
    events: list[SecurityEvent]
