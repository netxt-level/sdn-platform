from datetime import datetime
from ipaddress import IPv4Address
from typing import Any
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.flow import FlowMitigation


MAX_EVIDENCE_DEPTH = 4
MAX_EVIDENCE_STRING_LENGTH = 4096
MAX_EVIDENCE_LIST_LENGTH = 100
MAX_EVIDENCE_KEY_LENGTH = 128


def _validate_evidence_value(value: Any, *, depth: int = 0) -> Any:
    if depth > MAX_EVIDENCE_DEPTH:
        raise ValueError("evidence 중첩 깊이가 너무 큽니다.")

    if isinstance(value, str):
        if len(value) > MAX_EVIDENCE_STRING_LENGTH:
            raise ValueError("evidence 문자열 값이 너무 깁니다.")
        return value

    if isinstance(value, list):
        if len(value) > MAX_EVIDENCE_LIST_LENGTH:
            raise ValueError("evidence 리스트 값이 너무 깁니다.")
        for item in value:
            _validate_evidence_value(item, depth=depth + 1)
        return value

    if isinstance(value, dict):
        if len(value) > 80:
            raise ValueError("evidence 객체의 항목 수가 너무 많습니다.")
        for key, item in value.items():
            if len(str(key)) > MAX_EVIDENCE_KEY_LENGTH:
                raise ValueError("evidence key가 너무 깁니다.")
            _validate_evidence_value(item, depth=depth + 1)
        return value

    return value


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=80)
    event_fingerprint: str = Field(min_length=1, max_length=128)
    dedup_key: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    analyzer_id: str = Field(min_length=1, max_length=30)
    attack_category: Literal["FLOOD", "RECON"]
    attack_type: Literal["PORT_SCAN", "ICMP_FLOOD", "UDP_FLOOD", "SYN_FLOOD"]
    severity: Literal["low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    status: Literal["detected", "mitigating", "resolved", "failed"]
    src_ip: IPv4Address
    dst_ip: IPv4Address
    protocol: Literal["ICMP", "UDP", "TCP"]
    detection_rule: str = Field(min_length=1, max_length=128)
    recommended_action: Literal["log", "alert", "rate_limit", "drop"]
    response_level: Literal["L0", "L1", "L2", "L3"]
    evidence: dict[str, Any] = Field(max_length=80)
    mitigation: FlowMitigation | None = None

    @field_validator("evidence")
    @classmethod
    def validate_evidence_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_evidence_value(value)
        return value


class SecurityEventsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    analyzer_id: str = Field(min_length=1, max_length=30)
    events: list[SecurityEvent] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_event_analyzer_ids(self):
        for event in self.events:
            if event.analyzer_id != self.analyzer_id:
                raise ValueError(
                    "요청 analyzer_id와 event analyzer_id가 일치해야 합니다."
                )
        return self
