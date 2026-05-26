from fastapi import APIRouter

from app.api.ws import manager
from app.db.elasticsearch import index_detection_event
from app.db.elasticsearch import index_traffic_summary
from app.db.influxdb import write_detection_summary
from app.db.influxdb import write_packet_summary
from app.db.postgres import upsert_analyzer_status
from app.schemas.analyzer import (
    AnalyzerStatusRequest,
    DetectionSummaryRequest,
    PacketSummaryRequest,
)

router = APIRouter(prefix="/api/analyzer", tags=["analyzer"])


@router.post("/status")
async def receive_analyzer_status(payload: AnalyzerStatusRequest):
    data = payload.model_dump(mode="json")

    upsert_analyzer_status(data)

    await manager.broadcast({
        "type": "analyzer_status",
        "data": data,
    })

    return {"ok": True}


@router.post("/packet-summary")
async def receive_packet_summary(payload: PacketSummaryRequest):
    data = payload.model_dump(mode="json")

    write_packet_summary(data)
    index_traffic_summary(data)

    await manager.broadcast({
        "type": "packet_summary",
        "data": data,
    })

    return {"ok": True}


@router.post("/detection-summary")
async def receive_detection_summary(payload: DetectionSummaryRequest):
    data = payload.model_dump(mode="json")

    write_detection_summary(data)
    index_detection_event(data)

    await manager.broadcast({
        "type": "detection_summary",
        "data": data,
    })

    return {"ok": True}
