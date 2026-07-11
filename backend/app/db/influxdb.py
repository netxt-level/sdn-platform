import re
from datetime import datetime
from typing import Any

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

from app.core.config import settings

_DURATION_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 60 * 60,
    "d": 60 * 60 * 24,
    "w": 60 * 60 * 24 * 7,
}

# API payload의 timestamp 문자열을 InfluxDB에 넣을 수 있는 datetime으로 변경
def parse_timestamp(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value

    return datetime.fromisoformat(value.replace("Z", "+00:00"))

# InfluxDB 접속 클라이언트 생성
def get_influx_client() -> InfluxDBClient:
    return InfluxDBClient(
        url=settings.influxdb_url,
        token=settings.influxdb_token,
        org=settings.influxdb_org,
    )


def is_influxdb_ready() -> bool:
    client = get_influx_client()
    try:
        health = client.health()
        return str(getattr(health, "status", "")).lower() == "pass"
    except Exception:
        return False
    finally:
        client.close()


def validate_duration(value: str) -> str:
    if not re.fullmatch(r"[1-9][0-9]*[smhdw]", value):
        raise ValueError("Duration must look like 5s, 1m, 2h, 1d, or 1w")

    return value


def duration_to_seconds(value: str) -> int:
    validate_duration(value)
    return int(value[:-1]) * _DURATION_SECONDS[value[-1]]


def query_traffic_series(range_value: str, bucket_value: str) -> list[dict[str, Any]]:
    range_value = validate_duration(range_value)
    bucket_value = validate_duration(bucket_value)
    bucket_seconds = duration_to_seconds(bucket_value)

    query = f'''
from(bucket: "{settings.influxdb_bucket}")
  |> range(start: -{range_value})
  |> filter(fn: (r) => r["_measurement"] == "traffic_summary")
  |> filter(fn: (r) => r["_field"] == "total_packets" or r["_field"] == "total_bits")
  |> aggregateWindow(every: {bucket_value}, fn: sum, createEmpty: false)
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"])
'''

    client = get_influx_client()
    try:
        tables = client.query_api().query(query, org=settings.influxdb_org)

        items = []
        for table in tables:
            for record in table.records:
                values = record.values
                total_packets = int(values.get("total_packets") or 0)
                total_bits = int(values.get("total_bits") or 0)
                items.append({
                    "timestamp": values["_time"],
                    "total_packets": total_packets,
                    "total_bits": total_bits,
                    "pps": total_packets / bucket_seconds,
                    "bps": total_bits / bucket_seconds,
                })

        return items
    finally:
        client.close()


def query_protocol_stats(range_value: str) -> list[dict[str, Any]]:
    range_value = validate_duration(range_value)

    query = f'''
from(bucket: "{settings.influxdb_bucket}")
  |> range(start: -{range_value})
  |> filter(fn: (r) => r["_measurement"] == "protocol_stats")
  |> filter(fn: (r) => r["_field"] == "packet_count")
  |> group(columns: ["protocol"])
  |> sum(column: "_value")
  |> keep(columns: ["protocol", "_value"])
'''

    client = get_influx_client()
    try:
        tables = client.query_api().query(query, org=settings.influxdb_org)

        protocol_counts = []
        total_packets = 0
        for table in tables:
            for record in table.records:
                packet_count = int(record.get_value() or 0)
                total_packets += packet_count
                protocol_counts.append({
                    "protocol": record.values.get("protocol", "UNKNOWN"),
                    "packet_count": packet_count,
                })

        protocol_counts.sort(key=lambda item: item["packet_count"], reverse=True)
        for item in protocol_counts:
            item["percentage"] = round((item["packet_count"] / total_packets) * 100, 1) if total_packets else 0.0

        return protocol_counts
    finally:
        client.close()


# packet_summary 수신 패킷 데이터 저장
def write_packet_summary(summary: dict[str, Any]) -> None:

    # 입력 예:
    # {
    #   "timestamp": "2026-05-24T10:00:00+09:00",
    #   "analyzer_id": "analyzer-1",
    #   "window_sec": 1,
    #   "total_packets": 90,
    #   "total_bits": 273960,
    #   "protocol_stats": {"TCP": 87, "UDP": 2},
    #   "host_stats": [...]
    # }

    timestamp = parse_timestamp(summary["timestamp"])
    analyzer_id = summary["analyzer_id"]

    points = [
        Point("traffic_summary")
        .tag("analyzer_id", analyzer_id)
        .field("window_sec", float(summary["window_sec"]))
        .field("total_packets", int(summary["total_packets"]))
        .field("total_bits", int(summary["total_bits"]))
        .time(timestamp, WritePrecision.NS)
    ]

    # measurement: protocol_stats
    # TCP, UDP, UNKNOWN 같은 프로토콜별 패킷 수를 각각 별도 point로 저장
    for protocol, packet_count in summary.get("protocol_stats", {}).items():
        points.append(
            Point("protocol_stats")
            .tag("analyzer_id", analyzer_id)
            .tag("protocol", protocol)
            .field("packet_count", int(packet_count))
            .time(timestamp, WritePrecision.NS)
        )

    # measurement: host_traffic
    # 출발지/목적지/프로토콜 단위로 합산하고 대표 포트는 field로 남긴다.
    for host_stat in summary.get("host_stats", []):
        point = (
            Point("host_traffic")
            .tag("analyzer_id", analyzer_id)
            .tag("protocol", host_stat["protocol"])
            .field("packet_count", int(host_stat["packet_count"]))
            .field("bit_count", int(host_stat["bit_count"]))
            .time(timestamp, WritePrecision.NS)
        )

        # src_ip와 dst_ip는 필터링에 자주 쓰이므로 tag로 둔다.
        # port는 값 종류가 많아 tag 대신 field로 저장한다.
        if host_stat.get("src_ip"):
            point = point.tag("src_ip", host_stat["src_ip"])

        if host_stat.get("src_port") is not None:
            point = point.field("src_port", int(host_stat["src_port"]))

        if host_stat.get("dst_ip"):
            point = point.tag("dst_ip", host_stat["dst_ip"])

        if host_stat.get("dst_port") is not None:
            point = point.field("dst_port", int(host_stat["dst_port"]))

        points.append(point)

    client = get_influx_client()
    try:
        write_api = client.write_api(write_options=SYNCHRONOUS)

        # 여러 measurement의 point들을 한 번에 저장
        write_api.write(
            bucket=settings.influxdb_bucket,
            org=settings.influxdb_org,
            record=points,
        )
    finally:
        client.close()

# traffic_stats 수신 패킷 데이터 저장
def write_detection_summary(detection: dict[str, Any]) -> None:

    # 입력 예:
    # {
    #   "timestamp": "2026-05-24T10:00:00+09:00",
    #   "analyzer_id": "analyzer-1",
    #   "network_status": "warning",
    #   "total_bps": 273960.0,
    #   "total_pps": 90.0,
    #   "active_flow_count": 15
    # }

    timestamp = parse_timestamp(detection["timestamp"])
    analyzer_id = detection["analyzer_id"]

    points = [
        # measurement: network_status
        # 네트워크 전체 상태와 주요 수치 저장
        Point("network_status")
        .tag("analyzer_id", analyzer_id)
        .tag("network_status", detection["network_status"])
        .field("total_bps", float(detection["total_bps"]))
        .field("total_pps", float(detection["total_pps"]))
        .field("active_flow_count", int(detection["active_flow_count"]))
        .time(timestamp, WritePrecision.NS)
    ]

    client = get_influx_client()
    try:
        write_api = client.write_api(write_options=SYNCHRONOUS)

        # network_status point를 저장
        write_api.write(
            bucket=settings.influxdb_bucket,
            org=settings.influxdb_org,
            record=points,
        )
    finally:
        client.close()
