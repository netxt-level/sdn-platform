from fastapi import APIRouter
from fastapi import HTTPException
from pydantic import BaseModel, Field

from app.services.flow_service import FlowService
from app.services.flow_service import FlowRuleNotFoundError

router = APIRouter()
flow_service = FlowService()


class FlowRuleCreateRequest(BaseModel):
    switch_id: str | None = None
    match: dict = Field(default_factory=dict)
    action: str
    priority: int = Field(100, ge=1, le=65535)
    idle_timeout: int | None = Field(default=None, ge=0)
    hard_timeout: int | None = Field(default=None, ge=0)
    rate_limit_pps: int | None = Field(default=None, ge=1)


@router.get("")
def get_flows(src_ip: str | None = None):
    return flow_service.get_flows(src_ip)


@router.post("")
def create_flow(payload: FlowRuleCreateRequest):
    return flow_service.create_flow(payload.model_dump())


@router.delete("/{flow_rule_id}")
def delete_flow(flow_rule_id: str):
    try:
        return flow_service.delete_flow(flow_rule_id)
    except FlowRuleNotFoundError as error:
        raise HTTPException(
            status_code=404,
            detail=f"Flow Rule not found: {flow_rule_id}",
        ) from error
    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@router.post("/reconcile")
def reconcile_flows():
    return flow_service.reconcile_flows()
