from typing import Any

from app.repositories.security_event_repository import SecurityEventRepository
from app.repositories.traffic_repository import TrafficRepository


class DashboardService:
    def __init__(
        self,
        traffic_repository: TrafficRepository | None = None,
        security_event_repository: SecurityEventRepository | None = None,
    ):
        self.traffic_repository = traffic_repository or TrafficRepository()
        self.security_event_repository = (
            security_event_repository or SecurityEventRepository()
        )

    def get_summary(self) -> dict[str, Any]:
        return {
            "total_packets": 12000,
            "total_bytes": 8892301,
            "current_pps": 90.0,
            "current_bps": 273960.0,
            "network_status": "normal",
        }

    def get_traffic(self, range_value: str, bucket_value: str) -> dict[str, Any]:
        return {
            "range": range_value,
            "bucket": bucket_value,
            "items": self.traffic_repository.list_traffic_series(
                range_value,
                bucket_value,
            ),
        }

    def get_protocols(self, range_value: str) -> dict[str, Any]:
        return {
            "range": range_value,
            "items": self.traffic_repository.list_protocol_stats(range_value),
        }

    def get_suspicious_hosts(self, range_value: str) -> dict[str, Any]:
        items = self.security_event_repository.list_suspicious_hosts()

        return {
            "range": range_value,
            "count": len(items),
            "items": items,
        }
