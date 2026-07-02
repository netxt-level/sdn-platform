from typing import Any

from app.db.elasticsearch import index_traffic_summary
from app.db.influxdb import query_protocol_stats
from app.db.influxdb import query_suspicious_hosts
from app.db.influxdb import query_traffic_series
from app.db.influxdb import write_detection_summary
from app.db.influxdb import write_packet_summary


class TrafficRepository:
    def save_packet_summary(self, payload: dict[str, Any]) -> None:
        write_packet_summary(payload)
        index_traffic_summary(payload)

    def save_detection_summary_metrics(self, payload: dict[str, Any]) -> None:
        write_detection_summary(payload)

    def list_traffic_series(
        self,
        range_value: str,
        bucket_value: str,
    ) -> list[dict[str, Any]]:
        return query_traffic_series(range_value, bucket_value)

    def list_protocol_stats(self, range_value: str) -> list[dict[str, Any]]:
        return query_protocol_stats(range_value)

    def list_suspicious_hosts(self, range_value: str) -> list[dict[str, Any]]:
        return query_suspicious_hosts(range_value)
