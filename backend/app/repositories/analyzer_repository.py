from datetime import datetime
from typing import Any

from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.analyzer import Analyzer


def _parse_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value

    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _parse_required_datetime(value: Any) -> datetime:
    parsed = _parse_datetime(value)
    if parsed is None:
        raise ValueError("datetime value is required")

    return parsed


def _to_dict(analyzer: Analyzer) -> dict:
    return {
        "analyzer_id": analyzer.id,
        "status": analyzer.status,
        "interface": analyzer.interface,
        "capture_active": analyzer.capture_active,
        "backend_connected": analyzer.backend_connected,
        "last_packet_at": analyzer.last_packet_at,
        "last_summary_sent_at": analyzer.last_summary_sent_at,
        "error_message": analyzer.error_message,
        "pending_security_event_count": analyzer.pending_security_event_count,
        "dropped_security_event_count": analyzer.dropped_security_event_count,
        "packet_buffer_dropped_count": analyzer.packet_buffer_dropped_count,
        "last_security_event_send_failure": (
            analyzer.last_security_event_send_failure
        ),
        "reported_at": analyzer.reported_at,
        "created_at": analyzer.created_at,
        "updated_at": analyzer.updated_at,
    }


class AnalyzerRepository:
    def save_status(self, payload: dict) -> None:
        analyzer_id = payload["analyzer_id"]

        with SessionLocal.begin() as session:
            analyzer = session.get(Analyzer, analyzer_id)

            if analyzer is None:
                analyzer = Analyzer(id=analyzer_id)
                session.add(analyzer)

            analyzer.status = payload["status"]
            analyzer.interface = payload["interface"]
            analyzer.capture_active = payload["capture_active"]
            analyzer.backend_connected = payload["backend_connected"]
            analyzer.last_packet_at = _parse_datetime(payload.get("last_packet_at"))
            analyzer.last_summary_sent_at = _parse_datetime(
                payload.get("last_summary_sent_at"),
            )
            analyzer.error_message = payload.get("error_message")
            analyzer.pending_security_event_count = int(
                payload.get("pending_security_event_count") or 0
            )
            analyzer.dropped_security_event_count = int(
                payload.get("dropped_security_event_count") or 0
            )
            analyzer.packet_buffer_dropped_count = int(
                payload.get("packet_buffer_dropped_count") or 0
            )
            analyzer.last_security_event_send_failure = _parse_datetime(
                payload.get("last_security_event_send_failure")
            )
            analyzer.reported_at = _parse_required_datetime(payload["timestamp"])

    def list_statuses(self, analyzer_id: str | None = None) -> list[dict]:
        stmt = select(Analyzer).order_by(Analyzer.reported_at.desc())
        if analyzer_id:
            stmt = stmt.where(Analyzer.id == analyzer_id)

        with SessionLocal() as session:
            analyzers = session.execute(stmt).scalars().all()

        return [_to_dict(analyzer) for analyzer in analyzers]
