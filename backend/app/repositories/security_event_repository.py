from typing import Any

from app.db.elasticsearch import index_security_event
from app.db.elasticsearch import search_security_events


class SecurityEventRepository:
    def save_security_events(self, events: list[dict[str, Any]]) -> None:
        for event in events:
            index_security_event(event)

    def list_security_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return search_security_events(limit)
