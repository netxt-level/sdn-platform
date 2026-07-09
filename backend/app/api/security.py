from typing import Any

from fastapi import APIRouter, Query

from app.services.security_service import SecurityService

router = APIRouter()
security_service = SecurityService()


@router.get("/events")
def get_security_events(
    limit: int = Query(50, ge=1, le=500),
):
    """최근 보안 이벤트를 최신 순으로 조회한다."""

    return security_service.get_events(limit)


@router.post("/events")
async def receive_security_events(payload: dict[str, Any]):
    """Analyzer가 한 분석 창에서 만든 보안 이벤트 묶음을 받는다.

    API 계층은 HTTP 입출력만 담당하고, 저장과 실시간 전달은 service에
    맡긴다. 팀의 최신 dev와 통합할 때는 공용 Pydantic schema에 맞춰야 한다.
    """

    await security_service.receive_events(payload)

    return {"ok": True}
