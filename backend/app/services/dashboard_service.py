from __future__ import annotations

from typing import Any

from app.repositories.security_event_repository import SecurityEventRepository
from app.repositories.traffic_repository import TrafficRepository

SUMMARY_RANGE = "5m"
SUMMARY_BUCKET = "5s"
WARNING_BPS_THRESHOLD = 10_000_000
WARNING_PPS_THRESHOLD = 1500
CRITICAL_BPS_THRESHOLD = 20_000_000
CRITICAL_PPS_THRESHOLD = 3000
SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _host_rank(item: dict[str, Any]) -> tuple[int, float, float]:
    return (
        SEVERITY_RANK.get(str(item.get("severity") or "").lower(), 0),
        float(item.get("bps") or 0),
        float(item.get("pps") or 0),
    )


def deduplicate_suspicious_hosts(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return one representative suspicious-host entry for each source IP."""
    hosts_by_ip: dict[str, dict[str, Any]] = {}

    for item in items:
        ip = str(item.get("ip") or "").strip()
        if not ip:
            continue

        candidate = dict(item)
        candidate["ip"] = ip
        existing = hosts_by_ip.get(ip)
        if existing is None:
            candidate["reasons"] = list(
                dict.fromkeys(candidate.get("reasons") or [])
            )
            hosts_by_ip[ip] = candidate
            continue

        preferred = (
            candidate
            if _host_rank(candidate) > _host_rank(existing)
            else existing
        )
        merged = dict(preferred)
        merged["bps"] = max(
            float(existing.get("bps") or 0),
            float(candidate.get("bps") or 0),
        )
        merged["pps"] = max(
            float(existing.get("pps") or 0),
            float(candidate.get("pps") or 0),
        )
        merged["reasons"] = list(
            dict.fromkeys([
                *(existing.get("reasons") or []),
                *(candidate.get("reasons") or []),
            ])
        )
        hosts_by_ip[ip] = merged

    return sorted(
        hosts_by_ip.values(),
        key=lambda item: (*_host_rank(item), item["ip"]),
        reverse=True,
    )


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
        items = deduplicate_suspicious_hosts(
            self.security_event_repository.list_suspicious_hosts()
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
