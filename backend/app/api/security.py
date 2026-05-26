from fastapi import APIRouter, Query

from app.db.elasticsearch import search_detection_events

router = APIRouter()


@router.get("/events")
def get_security_events(
    limit: int = Query(50, ge=1, le=500),
):
    return {
        "limit": limit,
        "items": search_detection_events(limit),
    }
