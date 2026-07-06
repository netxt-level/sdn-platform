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
            "items": self.security_event_repository.list_security_events(limit),
        }

    async def receive_events(self, payload: dict[str, Any]) -> None:
        events = payload.get("events", [])
        self.security_event_repository.save_security_events(events)

        await manager.broadcast({
            "type": "security_events",
            "data": payload,
        })
