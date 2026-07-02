from fastapi import APIRouter

from app.services.flow_service import FlowService

router = APIRouter()
flow_service = FlowService()


@router.get("")
def get_flows(src_ip: str | None = None):
    return flow_service.get_flows(src_ip)
