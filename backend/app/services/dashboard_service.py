from __future__ import annotations

from typing import Any

from app.repositories.security_event_repository import SecurityEventRepository
from app.repositories.traffic_repository import TrafficRepository

SUMMARY_RANGE = "5m"
SUMMARY_BUCKET = "5s"
WARNING_BPS_THRESHOLD = 5_000_000
WARNING_PPS_THRESHOLD = 1000
CRITICAL_BPS_THRESHOLD = 10_000_000
CRITICAL_PPS_THRESHOLD = 3000


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
        traffic_items = self.traffic_repository.list_traffic_series(
            SUMMARY_RANGE,
            SUMMARY_BUCKET,
        )
        total_packets = sum(int(item.get("total_packets") or 0) for item in traffic_items)
        total_bits = sum(int(item.get("total_bits") or 0) for item in traffic_items)
        latest_item = traffic_items[-1] if traffic_items else {}
        current_pps = float(latest_item.get("pps") or 0)
        current_bps = float(latest_item.get("bps") or 0)

        return {
            "total_packets": total_packets,
            "total_bytes": int(total_bits / 8),
            "current_pps": current_pps,
            "current_bps": current_bps,
            "network_status": self._decide_network_status(
                current_bps=current_bps,
                current_pps=current_pps,
            ),
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
        items = self.security_event_repository.list_suspicious_hosts(
            range_value=range_value,
        )

        return {
            "range": range_value,
            "count": len(items),
            "items": items,
        }

    def _decide_network_status(
        self,
        *,
        current_bps: float,
        current_pps: float,
    ) -> str:
        if current_bps >= CRITICAL_BPS_THRESHOLD or current_pps >= CRITICAL_PPS_THRESHOLD:
            return "critical"

        if current_bps >= WARNING_BPS_THRESHOLD or current_pps >= WARNING_PPS_THRESHOLD:
            return "warning"

        return "normal"
