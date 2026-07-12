from datetime import datetime, timezone
from typing import Any


REUSABLE_FLOW_STATUSES = {"PENDING", "APPROVED", "APPLYING", "APPLIED"}
PENDING_REUSE_WINDOW_SECONDS = 600
APPROVED_REUSE_WINDOW_SECONDS = 600
APPLYING_REUSE_WINDOW_SECONDS = 300


def action_rank(action: str | None) -> int:
    return {
        "DROP": 3,
        "RATE_LIMIT": 2,
        "FORWARD": 1,
    }.get(str(action or "").upper(), 0)


def is_compatible_flow_rule(
    flow_rule: Any,
    mitigation: dict[str, Any],
    *,
    requested_action: str,
) -> bool:
    if not is_reusable_flow_rule(flow_rule):
        return False

    if _field(flow_rule, "switch_id") != mitigation.get("switch_id"):
        return False

    if (_field(flow_rule, "match") or {}) != (mitigation.get("match") or {}):
        return False

    if (_field(flow_rule, "target") or "flow") != mitigation.get("target", "flow"):
        return False

    if not _priority_is_strong_enough(
        existing_priority=_field(flow_rule, "priority"),
        requested_priority=mitigation.get("priority"),
    ):
        return False

    if not _timeout_is_strong_enough(
        flow_rule,
        field_name="idle_timeout",
        requested_timeout=mitigation.get("idle_timeout"),
    ):
        return False

    if not _timeout_is_strong_enough(
        flow_rule,
        field_name="hard_timeout",
        requested_timeout=mitigation.get("hard_timeout"),
    ):
        return False

    return is_action_strong_enough(
        existing_action=_field(flow_rule, "action"),
        requested_action=requested_action,
        existing_rate_limit_pps=_field(flow_rule, "rate_limit_pps"),
        requested_rate_limit_pps=mitigation.get("rate_limit_pps"),
    )


def is_action_strong_enough(
    *,
    existing_action: str | None,
    requested_action: str,
    existing_rate_limit_pps: int | None = None,
    requested_rate_limit_pps: int | None = None,
) -> bool:
    existing = str(existing_action or "").upper()
    requested = str(requested_action or "").upper()

    if existing == "DROP":
        return True

    if existing == "RATE_LIMIT" and requested == "RATE_LIMIT":
        if existing_rate_limit_pps is None or requested_rate_limit_pps is None:
            return False
        return int(existing_rate_limit_pps) <= int(requested_rate_limit_pps)

    return action_rank(existing) >= action_rank(requested)


def is_reusable_flow_rule(flow_rule: Any, *, now: datetime | None = None) -> bool:
    status = str(_field(flow_rule, "status") or "").upper()
    if status not in REUSABLE_FLOW_STATUSES:
        return False

    if status == "PENDING":
        return _is_recent_rule(
            flow_rule,
            candidate_fields=("created_at",),
            max_age_seconds=PENDING_REUSE_WINDOW_SECONDS,
            now=now,
        )

    if status == "APPROVED":
        return _is_recent_rule(
            flow_rule,
            candidate_fields=("updated_at", "created_at"),
            max_age_seconds=APPROVED_REUSE_WINDOW_SECONDS,
            now=now,
        )

    if status == "APPLYING":
        return _is_recent_rule(
            flow_rule,
            candidate_fields=("requested_at", "updated_at", "created_at"),
            max_age_seconds=APPLYING_REUSE_WINDOW_SECONDS,
            now=now,
        )

    if status != "APPLIED":
        return True

    applied_at = _field(flow_rule, "applied_at")
    if applied_at is None:
        return False

    hard_timeout = _field(flow_rule, "hard_timeout")
    if hard_timeout is None or int(hard_timeout) <= 0:
        return True

    current_time = _to_aware_datetime(now or datetime.now(timezone.utc))
    applied_at = _to_aware_datetime(applied_at)

    elapsed_seconds = (current_time - applied_at).total_seconds()
    return elapsed_seconds < int(hard_timeout)


def _is_recent_rule(
    flow_rule: Any,
    *,
    candidate_fields: tuple[str, ...],
    max_age_seconds: int,
    now: datetime | None = None,
) -> bool:
    base_time = None
    for field_name in candidate_fields:
        base_time = _field(flow_rule, field_name)
        if base_time is not None:
            break

    if base_time is None:
        return True

    current_time = _to_aware_datetime(now or datetime.now(timezone.utc))
    elapsed_seconds = (current_time - _to_aware_datetime(base_time)).total_seconds()
    return elapsed_seconds < max_age_seconds


def _field(flow_rule: Any, name: str) -> Any:
    if isinstance(flow_rule, dict):
        return flow_rule.get(name)
    return getattr(flow_rule, name, None)


def _priority_is_strong_enough(
    *,
    existing_priority: Any,
    requested_priority: Any,
) -> bool:
    if requested_priority is None:
        return True
    if existing_priority is None:
        return False
    return int(existing_priority) >= int(requested_priority)


def _timeout_is_strong_enough(
    flow_rule: Any,
    *,
    field_name: str,
    requested_timeout: Any,
) -> bool:
    if requested_timeout is None:
        return True

    requested = int(requested_timeout)
    if requested < 0:
        return False

    existing_timeout = _field(flow_rule, field_name)
    if existing_timeout is None:
        return False

    existing = int(existing_timeout)
    if requested == 0:
        return existing == 0

    if existing <= 0:
        return True

    if field_name != "hard_timeout":
        return existing >= requested

    applied_at = _field(flow_rule, "applied_at")
    if str(_field(flow_rule, "status") or "").upper() != "APPLIED" or applied_at is None:
        return existing >= requested

    current_time = datetime.now(timezone.utc)
    remaining = existing - (
        current_time - _to_aware_datetime(applied_at)
    ).total_seconds()
    return remaining >= requested


def _to_aware_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
