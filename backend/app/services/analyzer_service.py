from typing import Any

from app.core.websocket import manager
from app.repositories.analyzer_repository import AnalyzerRepository
from app.repositories.traffic_repository import TrafficRepository


class AnalyzerService:
    def __init__(
        self,
        analyzer_repository: AnalyzerRepository | None = None,
        traffic_repository: TrafficRepository | None = None,
    ):
        self.analyzer_repository = analyzer_repository or AnalyzerRepository()
        self.traffic_repository = traffic_repository or TrafficRepository()

    def list_statuses(self, analyzer_id: str | None = None) -> list[dict]:
        return self.analyzer_repository.list_statuses(analyzer_id)

    async def receive_status(self, payload: dict[str, Any]) -> None:
        self.analyzer_repository.save_status(payload)

        await manager.broadcast({
            "type": "analyzer_status",
            "data": payload,
        })

    async def receive_packet_summary(self, payload: dict[str, Any]) -> None:
        self.traffic_repository.save_packet_summary(payload)

        await manager.broadcast({
            "type": "packet_summary",
            "data": payload,
        })

    async def receive_detection_summary(self, payload: dict[str, Any]) -> None:
        self.traffic_repository.save_detection_summary_metrics(payload)

        await manager.broadcast({
            "type": "detection_summary",
            "data": payload,
        })
