from ipaddress import IPv4Address
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class FlowMatch(BaseModel):
    """Controller에 전달할 수 있는 IPv4 OpenFlow match 정보만 허용한다."""

    model_config = ConfigDict(extra="forbid")

    eth_type: Literal[2048] | None = None
    ipv4_src: IPv4Address | None = None
    ipv4_dst: IPv4Address | None = None
    ip_proto: Literal[1, 6, 17] | None = None
    tcp_src: int | None = Field(default=None, ge=1, le=65535)
    tcp_dst: int | None = Field(default=None, ge=1, le=65535)
    udp_src: int | None = Field(default=None, ge=1, le=65535)
    udp_dst: int | None = Field(default=None, ge=1, le=65535)
    icmpv4_type: int | None = Field(default=None, ge=0, le=255)
    icmpv4_code: int | None = Field(default=None, ge=0, le=255)

    @model_validator(mode="after")
    def validate_protocol_fields(self):
        fields = (
            self.eth_type,
            self.ipv4_src,
            self.ipv4_dst,
            self.ip_proto,
            self.tcp_src,
            self.tcp_dst,
            self.udp_src,
            self.udp_dst,
            self.icmpv4_type,
            self.icmpv4_code,
        )
        if not any(value is not None for value in fields):
            raise ValueError("match 조건은 하나 이상 필요합니다.")

        uses_ipv4_match = any(
            value is not None
            for value in (
                self.ipv4_src,
                self.ipv4_dst,
                self.ip_proto,
                self.tcp_src,
                self.tcp_dst,
                self.udp_src,
                self.udp_dst,
                self.icmpv4_type,
                self.icmpv4_code,
            )
        )
        if uses_ipv4_match and self.eth_type != 2048:
            raise ValueError("IPv4 match 조건에는 eth_type=2048이 필요합니다.")

        if (self.tcp_src is not None or self.tcp_dst is not None) and (
            self.ip_proto != 6
        ):
            raise ValueError("TCP 포트 조건에는 ip_proto=6이 필요합니다.")

        if (self.udp_src is not None or self.udp_dst is not None) and (
            self.ip_proto != 17
        ):
            raise ValueError("UDP 포트 조건에는 ip_proto=17이 필요합니다.")

        if (
            self.icmpv4_type is not None or self.icmpv4_code is not None
        ) and self.ip_proto != 1:
            raise ValueError("ICMP 조건에는 ip_proto=1이 필요합니다.")

        return self


class FlowRuleCreateRequest(BaseModel):
    """운영자가 수동으로 추가하는 Flow Rule 요청."""

    model_config = ConfigDict(extra="forbid")

    switch_id: str = Field(min_length=1, max_length=64)
    match: FlowMatch
    action: str
    priority: int = Field(100, ge=1, le=65535)
    idle_timeout: int | None = Field(default=None, ge=0)
    hard_timeout: int | None = Field(default=None, ge=0)
    rate_limit_pps: int | None = Field(default=None, ge=1)

    @field_validator("switch_id")
    @classmethod
    def validate_switch_id(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("switch_id는 비어 있을 수 없습니다.")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", normalized):
            raise ValueError("switch_id 형식이 올바르지 않습니다.")
        return normalized

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized in {"DROP", "RATE_LIMIT"}:
            return normalized

        # 기존 화면에서 쓰는 output:s2 형식은 허용하되 값 형태를 제한한다.
        if re.fullmatch(r"OUTPUT:[A-Z0-9_.:-]+", normalized):
            return normalized

        raise ValueError("action은 DROP, RATE_LIMIT, output:<port>만 허용합니다.")

    @model_validator(mode="after")
    def validate_action_options(self):
        if self.action == "RATE_LIMIT" and self.rate_limit_pps is None:
            raise ValueError("RATE_LIMIT action에는 rate_limit_pps가 필요합니다.")
        if self.action != "RATE_LIMIT" and self.rate_limit_pps is not None:
            raise ValueError(
                "RATE_LIMIT 이외 action에는 rate_limit_pps를 사용할 수 없습니다."
            )
        if self.action in {"DROP", "RATE_LIMIT"} and not _has_specific_match(
            self.match
        ):
            raise ValueError(
                "DROP/RATE_LIMIT action에는 IP, 포트, ICMP 타입 중 하나 이상의 구체적인 match가 필요합니다."
            )

        return self


class FlowMitigation(BaseModel):
    """Analyzer가 보안 이벤트와 함께 제안하는 자동 대응 후보."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["DROP", "RATE_LIMIT"]
    target: Literal["flow"] = "flow"
    match: FlowMatch
    priority: int = Field(ge=1, le=65535)
    idle_timeout: int | None = Field(default=None, ge=0)
    hard_timeout: int | None = Field(default=None, ge=0)
    rate_limit_pps: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_rate_limit(self):
        if self.action == "RATE_LIMIT" and self.rate_limit_pps is None:
            raise ValueError("RATE_LIMIT 대응에는 rate_limit_pps가 필요합니다.")
        if self.action != "RATE_LIMIT" and self.rate_limit_pps is not None:
            raise ValueError("DROP 대응에는 rate_limit_pps를 사용할 수 없습니다.")
        if not _has_specific_match(self.match):
            raise ValueError(
                "보안 대응 match에는 IP, 포트, ICMP 타입 중 하나 이상의 구체적인 조건이 필요합니다."
            )

        return self


def _has_specific_match(match: FlowMatch) -> bool:
    return any(
        value is not None
        for value in (
            match.ipv4_src,
            match.ipv4_dst,
            match.tcp_src,
            match.tcp_dst,
            match.udp_src,
            match.udp_dst,
            match.icmpv4_type,
        )
    )
