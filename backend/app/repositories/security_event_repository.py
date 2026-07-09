from typing import Any

from app.db.elasticsearch import index_detection_event
from app.db.elasticsearch import search_detection_events


class SecurityEventRepository:
    """Elasticsearch 보안 이벤트 저장소 접근을 한곳에 모은다."""

    def save_detection_event(self, payload: dict[str, Any]) -> None:
        """기존 detection summary 저장 흐름과의 호환 메서드."""

        index_detection_event(payload)

    def save_security_events(self, payload: dict[str, Any]) -> None:
        """Analyzer 요청에 포함된 개별 보안 이벤트를 각각 저장한다."""

        for event in payload.get("events", []):
            if not isinstance(event, dict):
                continue
            # 기존 인덱스 정렬 기준이 timestamp이므로 보안 이벤트 시각을 맞춰 준다.
            index_detection_event({
                **event,
                "timestamp": event.get("occurred_at") or event.get("created_at"),
            })

    def list_detection_events(self, limit: int = 50) -> list[dict[str, Any]]:
        """최신 문서부터 지정한 개수만 조회한다."""

        return search_detection_events(limit)
