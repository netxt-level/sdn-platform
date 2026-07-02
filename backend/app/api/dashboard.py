from fastapi import APIRouter, HTTPException, Query

from app.services.dashboard_service import DashboardService

router = APIRouter()
dashboard_service = DashboardService()

@router.get("/summary")
def get_dashboard_summary():
    return dashboard_service.get_summary()

@router.get("/traffic")
def get_traffic(
    range: str = Query("5m", pattern=r"^[1-9][0-9]*[smhdw]$"),
    bucket: str = Query("5s", pattern=r"^[1-9][0-9]*[smhdw]$"),
):
    try:
        return dashboard_service.get_traffic(range, bucket)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/protocols")
def get_protocols(
    range: str = Query("1m", pattern=r"^[1-9][0-9]*[smhdw]$"),
):
    try:
        return dashboard_service.get_protocols(range)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/suspicious-hosts")
def get_suspicious_hosts(
    range: str = Query("1w", pattern=r"^[1-9][0-9]*[smhdw]$"),
):
    try:
        return dashboard_service.get_suspicious_hosts(range)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
