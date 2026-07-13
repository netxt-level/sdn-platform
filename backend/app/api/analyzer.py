from fastapi import APIRouter, Depends

from app.core.auth import require_analyzer_api_key
from app.schemas.analyzer import (
    AnalyzerStatusRequest,
    DetectionSummaryRequest,
    PacketSummaryRequest,
)
from app.services.analyzer_service import AnalyzerService

router = APIRouter(prefix="/api/analyzer", tags=["analyzer"])
analyzer_service = AnalyzerService()


@router.get("/status")
def get_analyzer_status(analyzer_id: str | None = None):
    return {
        "items": analyzer_service.list_statuses(analyzer_id),
    }


@router.post("/status", dependencies=[Depends(require_analyzer_api_key)])
async def receive_analyzer_status(payload: AnalyzerStatusRequest):
    data = payload.model_dump(mode="json")
    await analyzer_service.receive_status(data)

    return {"ok": True}


@router.post("/packet-summary", dependencies=[Depends(require_analyzer_api_key)])
async def receive_packet_summary(payload: PacketSummaryRequest):
    data = payload.model_dump(mode="json")
    await analyzer_service.receive_packet_summary(data)

    return {"ok": True}


@router.post("/detection-summary", dependencies=[Depends(require_analyzer_api_key)])
async def receive_detection_summary(payload: DetectionSummaryRequest):
    data = payload.model_dump(mode="json")
    await analyzer_service.receive_detection_summary(data)

    return {"ok": True}
