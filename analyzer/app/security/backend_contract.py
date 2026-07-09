from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import AnalysisResult, EventStatus, MitigationAction, MitigationPolicy, SecurityEvent


# 프론트 보안 이벤트 화면이 공통으로 기대하는 최소 필드다.
# 엔진 내부 필드가 늘어나더라도 이 계약은 별도로 검증한다.
FRONTEND_EVENT_REQUIRED_FIELDS = {
    "id",
    "occurred_at",
    "attack_type",
    "severity",
    "status",
    "src_ip",
    "dst_ip",
    "protocol",
    "pps",
    "bps",
    "action",
}

FRONTEND_SEVERITIES = {"low", "medium", "high", "critical"}
FRONTEND_STATUSES = {"detected", "blocked", "ignored", "resolved"}
FRONTEND_ACTIONS = {"none", "block", "reroute"}


def event_to_backend_payload(event: SecurityEvent) -> dict[str, Any]:
    """엔진 이벤트를 저장과 화면 표시에 필요한 형태로 확장한다.

    canonical_*에는 엔진 원래 값을 보존하고, severity/status/action은 현재
    프론트엔드가 사용하는 소문자·단순 상태로 변환한다.
    """

    payload = event.to_dict()
    payload["id"] = event.event_id
    payload["occurred_at"] = event.created_at.isoformat()
    payload["canonical_severity"] = event.severity
    payload["canonical_status"] = event.status.value
    payload["canonical_action"] = event.action.value
    payload["severity"] = event.severity.lower()
    payload["status"] = _dashboard_status(event.status)
    payload["action"] = _dashboard_action(event.action)
    payload["pps"] = _event_pps(event)
    payload["bps"] = _event_bps(event)
    payload["mitigation_action"] = event.action.value
    payload["recommended_next_status"] = "Mitigating" if event.policy else "Detected"
    payload["dashboard_label"] = _dashboard_label(event)
    return payload


def event_to_frontend_payload(event: SecurityEvent) -> dict[str, Any]:
    """프론트가 반드시 알아야 하는 최소 필드만 추린다."""

    payload = event_to_backend_payload(event)
    return {field: payload[field] for field in FRONTEND_EVENT_REQUIRED_FIELDS}


def policy_to_controller_request(policy: MitigationPolicy) -> dict[str, Any]:
    """대응 정책 후보를 컨트롤러 요청으로 전달 가능한 구조로 만든다.

    현재 탐지 항목은 DROP과 RATE_LIMIT만 생성한다. reroute_path는 공용
    모델의 확장 호환 필드라서 현재 요청에서는 일반적으로 None이다.
    """

    return {
        "action": policy.action.value,
        "match": policy.match,
        "priority": policy.priority,
        "idle_timeout": policy.idle_timeout,
        "hard_timeout": policy.hard_timeout,
        "rate_limit_pps": policy.rate_limit_pps,
        "reroute_path": policy.reroute_path,
        "reason": policy.reason,
    }


def result_to_backend_payload(result: AnalysisResult) -> dict[str, Any]:
    """분석 요약, 개별 이벤트, 컨트롤러 정책 후보를 한 요청으로 묶는다."""

    return {
        "summary": {
            "window_seconds": result.window_seconds,
            "packet_count": result.packet_count,
            "event_count": len(result.events),
        },
        "events": [event_to_backend_payload(event) for event in result.events],
        "controller_requests": [policy_to_controller_request(policy) for policy in result.policies],
    }


def validate_backend_payload(payload: Mapping[str, Any]) -> list[str]:
    """백엔드로 보내기 전 계약 위반을 사람이 읽을 수 있는 목록으로 반환한다."""

    errors: list[str] = []
    summary = payload.get("summary")
    events = payload.get("events")
    controller_requests = payload.get("controller_requests")

    if not isinstance(summary, Mapping):
        errors.append("summary must be an object")
    else:
        for field in ("window_seconds", "packet_count", "event_count"):
            if field not in summary:
                errors.append(f"summary.{field} is required")

    if not isinstance(events, list):
        errors.append("events must be a list")
        events = []

    if not isinstance(controller_requests, list):
        errors.append("controller_requests must be a list")

    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            errors.append(f"events[{index}] must be an object")
            continue
        missing = sorted(FRONTEND_EVENT_REQUIRED_FIELDS - event.keys())
        for field in missing:
            errors.append(f"events[{index}].{field} is required")
        if event.get("severity") not in FRONTEND_SEVERITIES:
            errors.append(f"events[{index}].severity is invalid")
        if event.get("status") not in FRONTEND_STATUSES:
            errors.append(f"events[{index}].status is invalid")
        if event.get("action") not in FRONTEND_ACTIONS:
            errors.append(f"events[{index}].action is invalid")
        if not isinstance(event.get("attack_type"), str):
            errors.append(f"events[{index}].attack_type must be a string")
        for rate_field in ("pps", "bps"):
            if not isinstance(event.get(rate_field), int | float):
                errors.append(f"events[{index}].{rate_field} must be a number")

    return errors


def _dashboard_label(event: SecurityEvent) -> str:
    source = event.src_ip or event.src_mac or "network"
    target = event.dst_ip or event.evidence.get("link_id") or "network"
    return f"{event.attack_type}: {source} -> {target}"


def _dashboard_status(status: EventStatus) -> str:
    if status == EventStatus.MITIGATED:
        return "blocked"
    if status == EventStatus.RESOLVED:
        return "resolved"
    return "detected"


def _dashboard_action(action: MitigationAction) -> str:
    # 현재 UI의 block은 DROP뿐 아니라 RATE_LIMIT 후보도 포함하는 넓은 표현이다.
    # 실제 적용된 차단 상태는 이벤트 status와 Controller 결과로 구분해야 한다.
    if action == MitigationAction.REROUTE:
        return "reroute"
    if action in {MitigationAction.DROP, MitigationAction.RATE_LIMIT}:
        return "block"
    return "none"


def _event_pps(event: SecurityEvent) -> float:
    if event.metric_name == "pps" and isinstance(event.metric_value, int | float):
        return float(event.metric_value)
    for key in ("pps", "syn_pps"):
        value = event.evidence.get(key)
        if isinstance(value, int | float):
            return float(value)
    return 0.0


def _event_bps(event: SecurityEvent) -> float:
    if event.metric_name == "bps" and isinstance(event.metric_value, int | float):
        return float(event.metric_value)
    value = event.evidence.get("bps")
    if isinstance(value, int | float):
        return float(value)
    return 0.0
