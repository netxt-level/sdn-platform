from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import AnalysisResult, EventStatus, MitigationAction, MitigationPolicy, SecurityEvent


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
    payload = event_to_backend_payload(event)
    return {field: payload[field] for field in FRONTEND_EVENT_REQUIRED_FIELDS}


def policy_to_controller_request(policy: MitigationPolicy) -> dict[str, Any]:
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
