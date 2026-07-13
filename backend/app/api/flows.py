from fastapi import APIRouter, Depends
from fastapi import Query

from app.core.auth import require_admin_api_key
from app.schemas.flow import FlowRuleCreateRequest
from app.services.flow_service import FlowService

router = APIRouter()
flow_service = FlowService()


@router.get("")
def get_flows(
    src_ip: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    return flow_service.get_flows(src_ip, limit=limit, offset=offset)


@router.post("", dependencies=[Depends(require_admin_api_key)])
def create_flow(payload: FlowRuleCreateRequest):
    return flow_service.create_flow(payload.model_dump(mode="json", exclude_none=True))
