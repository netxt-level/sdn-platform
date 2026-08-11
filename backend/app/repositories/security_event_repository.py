from typing import Any

from app.db.elasticsearch import index_security_event
from app.db.elasticsearch import get_security_event
from app.db.elasticsearch import query_suspicious_hosts_from_security_events
from app.db.elasticsearch import search_security_events
from app.db.elasticsearch import update_security_event_status


class SecurityEventRepository:
    def save_security_events(self, events: list[dict[str, Any]]) -> None:
        for event in events:
            index_security_event(event)

    def list_security_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return search_security_events(limit)

    def get_security_event(self, event_id: str) -> dict[str, Any] | None:
        return get_security_event(event_id)

    def update_status(
        self,
        event_id: str,
        status: str,
    ) -> dict[str, Any] | None:
        return update_security_event_status(event_id, status)

    def list_suspicious_hosts(self, limit: int = 100) -> list[dict[str, Any]]:
        return query_suspicious_hosts_from_security_events(limit)
