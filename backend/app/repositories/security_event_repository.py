from typing import Any

from app.db.elasticsearch import index_security_events
from app.db.elasticsearch import query_suspicious_hosts_from_security_events
from app.db.elasticsearch import search_security_events


class SecurityEventRepository:
    def save_security_events(self, events: list[dict[str, Any]]) -> None:
        index_security_events(events)

    def list_security_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return search_security_events(limit)

    def list_suspicious_hosts(
        self,
        limit: int = 100,
        range_value: str | None = None,
    ) -> list[dict[str, Any]]:
        return query_suspicious_hosts_from_security_events(
            limit,
            range_value=range_value,
        )
