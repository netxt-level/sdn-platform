from typing import Any

from app.db.elasticsearch import index_detection_event
from app.db.elasticsearch import search_detection_events


class SecurityEventRepository:
    def save_detection_event(self, payload: dict[str, Any]) -> None:
        index_detection_event(payload)

    def list_detection_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return search_detection_events(limit)
