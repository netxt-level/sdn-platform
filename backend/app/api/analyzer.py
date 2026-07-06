from fastapi import APIRouter

from app.schemas.analyzer import (
    AnalyzerChangeMessageRequest,
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


@router.post("/status")
async def receive_analyzer_status(payload: AnalyzerStatusRequest):
    data = payload.model_dump(mode="json")
    await analyzer_service.receive_status(data)

    return {"ok": True}


@router.post("/packet-summary")
async def receive_packet_summary(payload: PacketSummaryRequest):
    data = payload.model_dump(mode="json")
    await analyzer_service.receive_packet_summary(data)

    return {"ok": True}


@router.post("/detection-summary")
async def receive_detection_summary(payload: DetectionSummaryRequest):
    data = payload.model_dump(mode="json")
    await analyzer_service.receive_detection_summary(data)

    return {"ok": True}


@router.post("/changes")
async def receive_analyzer_change(payload: AnalyzerChangeMessageRequest):
    data = payload.model_dump(mode="json")
    await analyzer_service.receive_change_message(data)

    return {"ok": True}
