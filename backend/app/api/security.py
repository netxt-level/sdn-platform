from fastapi import APIRouter, Query

from app.schemas.security import SecurityEventsRequest
from app.services.security_service import SecurityService

router = APIRouter()
security_service = SecurityService()


@router.get("/events")
def get_security_events(
    limit: int = Query(50, ge=1, le=500),
):
    return security_service.get_events(limit)


@router.post("/events")
async def receive_security_events(payload: SecurityEventsRequest):
    data = payload.model_dump(mode="json")
    await security_service.receive_events(data)

    return {"ok": True}
