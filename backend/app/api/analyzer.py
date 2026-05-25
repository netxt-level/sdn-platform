from fastapi import APIRouter

from app.db.elasticsearch import index_detection_event, index_traffic_summary
from app.db.influxdb import write_detection_summary, write_packet_summary
from app.db.postgres import upsert_analyzer_status
from app.schemas.analyzer import (
    AnalyzerStatusRequest,
    DetectionSummaryRequest,
    PacketSummaryRequest,
)

# Analyzer 관련 API를 묶는 라우터
router = APIRouter(prefix="/api/analyzer", tags=["analyzer"])

# 분석 서버의 상태 정보를 수신하는 API
@router.post("/status")
def receive_analyzer_status(payload: AnalyzerStatusRequest):
    # Pydantic 모델을 dict로 변환한 뒤 PostgreSQL에 analyzer 상태를 저장/갱신
    upsert_analyzer_status(payload.model_dump())

    # 정상 처리 시 HTTP 200 OK 응답
    return {"ok": True}


# 분석 서버가 일정 시간 동안 수집한 패킷 요약 정보를 수신하는 API
@router.post("/packet-summary")
def receive_packet_summary(payload: PacketSummaryRequest):
    data = payload.model_dump(mode="json")
    write_packet_summary(data)
    index_traffic_summary(data)

    # 정상 처리 시 HTTP 200 OK 응답
    return {"ok": True}

# 분석 서버가 계산한 탐지/트래픽 상태 요약 정보를 수신하는 API
@router.post("/detection-summary")
def receive_detection_summary(payload: DetectionSummaryRequest):
    data = payload.model_dump(mode="json")
    write_detection_summary(data)
    index_detection_event(data)

    # 정상 처리 시 HTTP 200 OK와 함께 응답
    return {"ok": True}