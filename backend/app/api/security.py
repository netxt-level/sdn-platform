from fastapi import APIRouter, HTTPException, Query

from app.schemas.security import SecurityEventActionRequest
from app.schemas.security import SecurityEventsRequest
from app.services.security_service import SecurityService

router = APIRouter()
security_service = SecurityService()


@router.get("/events")
def get_security_events(
    limit: int = Query(50, ge=1, le=500),
):
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


@router.post("/events/{event_id}/actions")
def respond_to_security_event(
    event_id: str,
    payload: SecurityEventActionRequest,
):
    try:
        return security_service.respond_to_event(event_id, payload.action)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="security event not found") from exc
