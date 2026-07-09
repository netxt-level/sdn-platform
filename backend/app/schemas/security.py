from datetime import datetime
from typing import Any

from pydantic import BaseModel


class SecurityEvent(BaseModel):
    event_id: str
    event_fingerprint: str
    dedup_key: str
    timestamp: datetime
    analyzer_id: str
    attack_category: str
    attack_type: str
    severity: str
    confidence: str
    status: str
    # ARP Spoofing에서는 공격자의 신뢰할 수 있는 IP가 없을 수 있다.
    src_ip: str | None = None
    src_mac: str | None = None
    dst_ip: str
    protocol: str
    detection_rule: str
    recommended_action: str
    response_level: str
    evidence: dict[str, Any]
    mitigation: dict[str, Any] | None = None


class SecurityEventsRequest(BaseModel):
    timestamp: datetime
    analyzer_id: str
    events: list[SecurityEvent]
