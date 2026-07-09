from fastapi import APIRouter, Query

from app.schemas.security import SecurityEventsRequest
from app.services.security_service import SecurityService

router = APIRouter()
security_service = SecurityService()


@router.get("/events")
def get_security_events(
    limit: int = Query(50, ge=1, le=500),
):
    """최근 보안 이벤트를 최신 순으로 조회한다."""

    return security_service.get_events(limit)


@router.get("/responses")
def get_security_responses(
    limit: int = Query(50, ge=1, le=500),
):
    return security_service.get_responses(limit)


@router.post("/events")
async def receive_security_events(payload: SecurityEventsRequest):
    data = payload.model_dump(mode="json")
    await security_service.receive_events(data)

    return {"ok": True}
