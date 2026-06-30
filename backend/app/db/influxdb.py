import os
import re
from datetime import datetime
from typing import Any

from dotenv import load_dotenv
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

load_dotenv()

_DURATION_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 60 * 60,
    "d": 60 * 60 * 24,
    "w": 60 * 60 * 24 * 7,
}

# env 파일 환경변수 확인
def get_env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value

# API payload의 timestamp 문자열을 InfluxDB에 넣을 수 있는 datetime으로 변경
def parse_timestamp(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value

    return datetime.fromisoformat(value.replace("Z", "+00:00"))

# InfluxDB 접속 클라이언트 생성
def get_influx_client() -> InfluxDBClient:
    host = get_env("INFLUXDB_HOST", "localhost")
    port = get_env("INFLUXDB_PORT", "8086")

    return InfluxDBClient(
        url=f"http://{host}:{port}",
        token=get_env("INFLUXDB_TOKEN"),
        org=get_env("INFLUXDB_ORG"),
    )


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
from(bucket: "{get_env("INFLUXDB_BUCKET")}")
  |> range(start: -{range_value})
  |> filter(fn: (r) => r["_measurement"] == "traffic_summary")
  |> filter(fn: (r) => r["_field"] == "total_packets" or r["_field"] == "total_bits")
  |> aggregateWindow(every: {bucket_value}, fn: sum, createEmpty: false)
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"])
'''

    client = get_influx_client()
    try:
        tables = client.query_api().query(query, org=get_env("INFLUXDB_ORG"))

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
from(bucket: "{get_env("INFLUXDB_BUCKET")}")
  |> range(start: -{range_value})
  |> filter(fn: (r) => r["_measurement"] == "protocol_stats")
  |> filter(fn: (r) => r["_field"] == "packet_count")
  |> group(columns: ["protocol"])
  |> sum(column: "_value")
  |> keep(columns: ["protocol", "_value"])
'''

    client = get_influx_client()
    try:
        tables = client.query_api().query(query, org=get_env("INFLUXDB_ORG"))

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


def infer_suspicious_host_attack_type(
    suspicious_host: dict[str, Any],
) -> str:
    attack_type = suspicious_host.get("attack_type")

    if attack_type:
        return str(attack_type).upper()

    reasons = " ".join(suspicious_host.get("reasons", [])).lower()

    if "port scan" in reasons or "scan" in reasons:
        return "PORT_SCAN"

    return "DOS"


def query_suspicious_hosts(range_value: str) -> list[dict[str, Any]]:
    range_value = validate_duration(range_value)

    query = f'''
from(bucket: "{get_env("INFLUXDB_BUCKET")}")
  |> range(start: -{range_value})
  |> filter(fn: (r) => r["_measurement"] == "suspicious_host_traffic")
  |> filter(fn: (r) => r["_field"] == "bps" or r["_field"] == "pps" or r["_field"] == "reason")
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> group(columns: ["analyzer_id", "ip", "protocol", "attack_type"])
  |> sort(columns: ["_time"], desc: true)
  |> limit(n: 1)
'''

    client = get_influx_client()
    try:
        tables = client.query_api().query(query, org=get_env("INFLUXDB_ORG"))

        items = []
        for table in tables:
            for record in table.records:
                values = record.values
                ip = values.get("ip")

                if not ip:
                    continue

                reason = values.get("reason")
                item = {
                    "timestamp": values["_time"],
                    "analyzer_id": values.get("analyzer_id"),
                    "host": values.get("host"),
                    "ip": ip,
                    "protocol": values.get("protocol", "UNKNOWN"),
                    "bps": float(values.get("bps") or 0),
                    "pps": float(values.get("pps") or 0),
                    "reasons": [reason] if reason else ["stored suspicious host"],
                    "attack_type": values.get("attack_type"),
                }
                item["attack_type"] = infer_suspicious_host_attack_type(item)
                items.append(item)

        items.sort(
            key=lambda item: (item["bps"], item["pps"], item["ip"]),
            reverse=True,
        )

        return items
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
        .field("window_sec", int(summary["window_sec"]))
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
    # src_ip -> dst_ip 단위의 트래픽 수치를 저장
    for host_stat in summary.get("host_stats", []):
        point = (
            Point("host_traffic")
            .tag("analyzer_id", analyzer_id)
            .tag("protocol", host_stat["protocol"])
            .field("packet_count", int(host_stat["packet_count"]))
            .field("bit_count", int(host_stat["bit_count"]))
            .time(timestamp, WritePrecision.NS)
        )

        # src_ip, dst_ip는 필터링에 자주 쓸 수 있어서 tag로 둔다.
        # 값이 null이면 tag로 넣지 않는다.
        if host_stat.get("src_ip"):
            point = point.tag("src_ip", host_stat["src_ip"])

        if host_stat.get("dst_ip"):
            point = point.tag("dst_ip", host_stat["dst_ip"])

        points.append(point)

    client = get_influx_client()
    try:
        write_api = client.write_api(write_options=SYNCHRONOUS)

        # 여러 measurement의 point들을 한 번에 저장
        write_api.write(
            bucket=get_env("INFLUXDB_BUCKET"),
            org=get_env("INFLUXDB_ORG"),
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
    #   "active_flow_count": 15,
    #   "suspicious_host_count": 1,
    #   "suspicious_hosts": [...]
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
        .field("suspicious_host_count", int(detection["suspicious_host_count"]))
        .time(timestamp, WritePrecision.NS)
    ]

    # measurement: suspicious_host_traffic
    # 의심 호스트별 bps/pps를 저장
    for suspicious_host in detection.get("suspicious_hosts", []):
        reasons = suspicious_host.get("reasons", [])
        reason = "; ".join(reasons) if reasons else "suspicious host detected"
        attack_type = infer_suspicious_host_attack_type(suspicious_host)
        point = (
            Point("suspicious_host_traffic")
            .tag("analyzer_id", analyzer_id)
            .tag("ip", suspicious_host["ip"])
            .tag("protocol", suspicious_host["protocol"])
            .tag("attack_type", attack_type)
            .field("bps", float(suspicious_host["bps"]))
            .field("pps", float(suspicious_host["pps"]))
            .field("reason", reason)
            .time(timestamp, WritePrecision.NS)
        )

        # host 이름이 있으면 tag로 추가
        if suspicious_host.get("host"):
            point = point.tag("host", suspicious_host["host"])

        points.append(point)

    client = get_influx_client()
    try:
        write_api = client.write_api(write_options=SYNCHRONOUS)

        # network_status와 suspicious_host_traffic point들을 저장
        write_api.write(
            bucket=get_env("INFLUXDB_BUCKET"),
            org=get_env("INFLUXDB_ORG"),
            record=points,
        )
    finally:
        client.close()
