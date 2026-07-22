from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

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

        try:
            with SessionLocal.begin() as session:
                response = None
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
                        decision_reason=(
                            "created from analyzer security event recommendation"
                        ),
                        mitigation=event.get("mitigation"),
                        response_payload=None,
                        detected_at=_parse_datetime(event.get("timestamp")),
                    )
                    session.add(response)
                    session.flush()

                return _to_dict(response)
        except IntegrityError:
            # 동일 Outbox 이벤트가 동시에 재전송돼도 event_id 고유 제약으로
            # 한 사건만 남기고 이미 생성된 응답을 반환한다.
            if not event_id:
                raise
            with SessionLocal() as session:
                stmt = select(SecurityResponse).where(
                    SecurityResponse.source_event_id == event_id,
                    SecurityResponse.response_action == response_action,
                )
                response = session.execute(stmt).scalar_one_or_none()
            if response is None:
                raise
            return _to_dict(response)

    def update_status(
        self,
        response_id: str,
        *,
        status: str,
        response_payload: dict[str, Any] | None = None,
        decision_reason: str | None = None,
        approved_by: str | None = None,
        approved_at: datetime | None = None,
        requested_at: datetime | None = None,
        completed_at: datetime | None = None,
        error_message: str | None = None,
    ) -> dict[str, Any] | None:
        with SessionLocal.begin() as session:
            response = session.get(SecurityResponse, response_id)
            if response is None:
                return None

            response.status = status
            response.response_payload = response_payload
            if decision_reason is not None:
                response.decision_reason = decision_reason
            response.approved_by = approved_by
            response.approved_at = approved_at
            response.requested_at = requested_at
            response.completed_at = completed_at
            response.error_message = error_message

            return _to_dict(response)
