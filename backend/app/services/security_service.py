from typing import Any

from app.core.websocket import manager
from app.repositories.security_event_repository import SecurityEventRepository


class SecurityService:
    def __init__(
        self,
        security_event_repository: SecurityEventRepository | None = None,
    ):
        self.security_event_repository = (
            security_event_repository or SecurityEventRepository()
        )

    def get_events(self, limit: int) -> dict[str, Any]:
        return {
            "limit": limit,
            "items": self.security_event_repository.list_detection_events(limit),
        }

    async def receive_events(self, payload: dict[str, Any]) -> None:
        self.security_event_repository.save_security_events(payload)

        for event in payload.get("events", []):
            if not isinstance(event, dict):
                continue
            await manager.broadcast({
                "type": "security_event",
                "data": event,
            })
