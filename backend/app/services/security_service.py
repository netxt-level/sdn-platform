from typing import Any

from app.core.websocket import manager
from app.repositories.security_event_repository import SecurityEventRepository


class SecurityService:
    """보안 이벤트 저장과 WebSocket 전달 순서를 조정하는 서비스."""

    def __init__(
        self,
        security_event_repository: SecurityEventRepository | None = None,
    ):
        self.security_event_repository = (
            security_event_repository or SecurityEventRepository()
        )

    def get_events(self, limit: int) -> dict[str, Any]:
        """repository 조회 결과를 API 응답 형식으로 감싼다."""

        return {
            "limit": limit,
            "items": self.security_event_repository.list_detection_events(limit),
        }

    async def receive_events(self, payload: dict[str, Any]) -> None:
        """이벤트를 먼저 저장한 뒤 연결된 화면에 실시간으로 전달한다."""

        self.security_event_repository.save_security_events(payload)

        # 한 요청에 여러 이벤트가 들어올 수 있으므로 화면에는 사건별로 방송한다.
        for event in payload.get("events", []):
            if not isinstance(event, dict):
                continue
            await manager.broadcast({
                "type": "security_event",
                "data": event,
            })
