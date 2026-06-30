from fastapi import APIRouter, HTTPException, Query

from app.db.influxdb import query_protocol_stats
from app.db.influxdb import query_suspicious_hosts
from app.db.influxdb import query_traffic_series

router = APIRouter()

@router.get("/summary")
def get_dashboard_summary():
    return {
        "total_packets": 12000,
        "total_bytes": 8892301,
        "current_pps": 90.0,
        "current_bps": 273960.0,
        "network_status": "normal",
    }

@router.get("/traffic")
def get_traffic(
    range: str = Query("5m", pattern=r"^[1-9][0-9]*[smhdw]$"),
    bucket: str = Query("5s", pattern=r"^[1-9][0-9]*[smhdw]$"),
):
    try:
        return {
            "range": range,
            "bucket": bucket,
            "items": query_traffic_series(range, bucket),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/protocols")
def get_protocols(
    range: str = Query("1m", pattern=r"^[1-9][0-9]*[smhdw]$"),
):
    try:
        return {
            "range": range,
            "items": query_protocol_stats(range),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/suspicious-hosts")
def get_suspicious_hosts(
    range: str = Query("1w", pattern=r"^[1-9][0-9]*[smhdw]$"),
):
    try:
        items = query_suspicious_hosts(range)

        return {
            "range": range,
            "count": len(items),
            "items": items,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
