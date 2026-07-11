from fastapi import APIRouter

from app.schemas.flow import FlowRuleCreateRequest
from app.services.flow_service import FlowService

router = APIRouter()
flow_service = FlowService()


@router.get("")
def get_flows(src_ip: str | None = None):
    return flow_service.get_flows(src_ip)


@router.post("")
def create_flow(payload: FlowRuleCreateRequest):
    return flow_service.create_flow(payload.model_dump(mode="json", exclude_none=True))
