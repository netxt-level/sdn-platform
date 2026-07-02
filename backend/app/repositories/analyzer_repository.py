from app.db.postgres import get_analyzer_statuses
from app.db.postgres import upsert_analyzer_status


class AnalyzerRepository:
    def save_status(self, payload: dict) -> None:
        upsert_analyzer_status(payload)

    def list_statuses(self, analyzer_id: str | None = None) -> list[dict]:
        return get_analyzer_statuses(analyzer_id)
