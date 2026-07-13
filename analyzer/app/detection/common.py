from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Address, ip_address
from typing import Any


def current_time() -> datetime:
    """탐지 기준 시간을 UTC 기준으로 통일한다."""

    return datetime.now(timezone.utc)


def packet_time(packet: dict[str, Any], fallback: datetime) -> datetime:
    """패킷에 기록된 timestamp를 datetime으로 바꾼다.

    테스트 데이터나 일부 캡처 환경에서는 timestamp가 없을 수 있으므로,
    값이 없거나 변환할 수 없으면 호출 시점의 fallback 값을 사용한다.
    """

    value = packet.get("timestamp")
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return fallback


def to_int(value: Any) -> int | None:
    """문자열로 들어온 포트 번호나 패킷 수를 안전하게 정수로 바꾼다."""

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def to_port(value: Any) -> int | None:
    """TCP/UDP 포트 번호를 유효 범위 안에서만 반환한다."""

    port = to_int(value)
    if port is None or not 1 <= port <= 65535:
        return None
    return port


def to_ip(value: Any) -> str | None:
    """OpenFlow IPv4 match에 안전하게 넣을 수 있는 IPv4 주소만 반환한다."""

    try:
        address = ip_address(str(value))
    except (TypeError, ValueError):
        return None
    if not isinstance(address, IPv4Address):
        return None
    return str(address)


def clamp_score(score: int | float) -> int:
    """탐지 점수를 0점에서 100점 사이로 제한한다."""

    return max(0, min(int(score), 100))


def score_policy(score: int, *, drop_allowed: bool = True) -> tuple[str, str, str]:
    """공통 점수표에 따라 위험도, 대응 단계, 권장 대응을 반환한다.

    drop_allowed가 False인 탐지는 Critical이어도 바로 Drop 후보를 만들지 않고
    Rate Limit 후보까지만 만든다. 정상 점검과 비슷한 Port Scan에 사용한다.
    """

    if score <= 44:
        return "low", "L0", "log"
    if score <= 69:
        return "medium", "L1", "alert"
    if score <= 84:
        return "high", "L2", "rate_limit"
    if drop_allowed:
        return "critical", "L3", "drop"
    return "critical", "L2", "rate_limit"
