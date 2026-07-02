from typing import Any

from app.repositories.traffic_repository import TrafficRepository


class DashboardService:
    def __init__(self, traffic_repository: TrafficRepository | None = None):
        self.traffic_repository = traffic_repository or TrafficRepository()

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
        items = self.traffic_repository.list_suspicious_hosts(range_value)

        return {
            "range": range_value,
            "count": len(items),
            "items": items,
        }
