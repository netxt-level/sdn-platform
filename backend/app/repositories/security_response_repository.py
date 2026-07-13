from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.security_response import SecurityResponse


def _parse_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value

    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _to_dict(response: SecurityResponse) -> dict[str, Any]:
    return {
        "id": response.id,
        "source_event_id": response.source_event_id,
        "source_event_fingerprint": response.source_event_fingerprint,
        "analyzer_id": response.analyzer_id,
        "attack_category": response.attack_category,
        "attack_type": response.attack_type,
        "severity": response.severity,
        "recommended_action": response.recommended_action,
        "response_action": response.response_action,
        "response_level": response.response_level,
        "status": response.status,
        "decision_reason": response.decision_reason,
        "mitigation": response.mitigation,
        "response_payload": response.response_payload,
        "approved_by": response.approved_by,
        "detected_at": response.detected_at,
        "approved_at": response.approved_at,
        "requested_at": response.requested_at,
        "completed_at": response.completed_at,
        "error_message": response.error_message,
        "created_at": response.created_at,
        "updated_at": response.updated_at,
    }


def _response_action_from_event(event: dict[str, Any]) -> str:
    mitigation = event.get("mitigation") or {}
    action = mitigation.get("action") or event.get("recommended_action") or "MONITOR"

    return str(action).upper()


def _initial_status_from_action(response_action: str) -> str:
    """실제 Flow 조치가 없는 이벤트는 대기 상태로 남기지 않는다."""

    if response_action in {"RATE_LIMIT", "DROP"}:
        return "PENDING"
    return "RECORDED"


class SecurityResponseRepository:
    def list_responses(self, limit: int = 50) -> list[dict[str, Any]]:
        stmt = (
            select(SecurityResponse)
            .order_by(SecurityResponse.created_at.desc())
            .limit(limit)
        )

        with SessionLocal() as session:
            responses = session.execute(stmt).scalars().all()

        return [_to_dict(response) for response in responses]

    def get_or_create_from_event(self, event: dict[str, Any]) -> dict[str, Any]:
        response_action = _response_action_from_event(event)
        event_id = event.get("event_id")
        fingerprint = event.get("event_fingerprint")

        with SessionLocal.begin() as session:
            response = None
            now = datetime.now(timezone.utc)
            initial_status = _initial_status_from_action(response_action)
            if event_id:
                stmt = select(SecurityResponse).where(
                    SecurityResponse.source_event_id == event_id,
                    SecurityResponse.response_action == response_action,
                )
                response = session.execute(stmt).scalar_one_or_none()

            if response is None:
                response = SecurityResponse(
                    source_event_id=event_id,
                    source_event_fingerprint=fingerprint,
                    analyzer_id=event["analyzer_id"],
                    attack_category=event.get("attack_category"),
                    attack_type=event.get("attack_type"),
                    severity=event.get("severity"),
                    recommended_action=event.get("recommended_action"),
                    response_action=response_action,
                    response_level=event.get("response_level"),
                    status=initial_status,
                    decision_reason=(
                        "created from analyzer security event recommendation"
                    ),
                    mitigation=event.get("mitigation"),
                    response_payload=None,
                    detected_at=_parse_datetime(event.get("timestamp")),
                    completed_at=now if initial_status == "RECORDED" else None,
                )
                session.add(response)
                session.flush()

            return _to_dict(response)

    def link_flow_rule(
        self,
        response_id: str,
        flow_rule: dict[str, Any],
    ) -> dict[str, Any] | None:
        with SessionLocal.begin() as session:
            response = session.get(SecurityResponse, response_id)
            if response is None:
                return None

            response.response_payload = {
                **(response.response_payload or {}),
                "flow_rule_id": flow_rule.get("id"),
                "flow_rule_reused": bool(flow_rule.get("flow_rule_reused")),
                "flow_rule_action": flow_rule.get("action"),
                "flow_rule_switch_id": flow_rule.get("switch_id"),
                "flow_rule_match": flow_rule.get("match"),
            }
            response.updated_at = datetime.now(timezone.utc)
            return _to_dict(response)
