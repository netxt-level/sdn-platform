from datetime import datetime
from typing import Any
from typing import Literal

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
    src_ip: str
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


class SecurityEventActionRequest(BaseModel):
    action: Literal["block", "ignore", "resolve"]
