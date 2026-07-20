"""REST API for controller health, switches, and external Flow Rules."""

from threading import Thread

from fastapi import FastAPI
from fastapi import HTTPException
from pydantic import BaseModel
from pydantic import Field
import uvicorn

from app.flow_manager import build_external_flow_cookie
from app.flow_manager import install_external_flow_with_barrier
from app.topology import SWITCH_LINK_PORTS


FLOW_CONFIRM_TIMEOUT_SECONDS = 5.0


class FlowRuleInstallRequest(BaseModel):
    rule_id: str = Field(min_length=1, max_length=128)
    switch_id: str = Field(min_length=1, max_length=64)
    match: dict
    action: str = Field(min_length=1, max_length=64)
    priority: int = Field(ge=1, le=65535)
    idle_timeout: int | None = Field(default=None, ge=0, le=65535)
    hard_timeout: int | None = Field(default=None, ge=0, le=65535)


def parse_switch_dpid(switch_id):
    value = str(switch_id).strip().lower()
    if value.startswith("s") and value[1:].isdigit():
        return int(value[1:])
    if value.startswith("0x"):
        return int(value, 16)
    if value.isdigit():
        return int(value)
    if len(value) == 16:
        try:
            return int(value, 16)
        except ValueError:
            pass
    raise ValueError(f"invalid switch_id: {switch_id}")


def build_flow_operation_response(status):
    return {
        "controller_rule_id": status.rule_id,
        "switch_id": status.switch_id,
        "dpid": f"{status.dpid:016x}",
        "cookie": f"0x{status.cookie:016x}",
        "status": (
            "APPLIED" if status.state == "installed" else status.state.upper()
        ),
        "flow_xid": status.flow_xid,
        "barrier_xid": status.barrier_xid,
        "error": status.error,
    }


def build_health_response(datapaths, settings):
    return {
        "status": "ready",
        "openflow_version": "1.3",
        "openflow_port": settings.openflow_port,
        "rest_port": settings.rest_port,
        "connected_switches": len(datapaths),
    }


def build_switches_response(datapaths, table_miss_statuses):
    switches = []
    for datapath in datapaths.snapshot():
        status = table_miss_statuses.get(datapath)
        state = "unknown" if status is None else status.state
        switches.append({
            "dpid": f"{datapath.id:016x}",
            "state": "connected",
            "table_miss_state": state,
            "table_miss_installed": state == "installed",
            "table_miss_error": None if status is None else status.error,
        })

    return {
        "switches": switches,
    }


def create_api(datapaths, table_miss_statuses, flow_operations, settings):
    app = FastAPI(
        title="SDN Controller API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health")
    def health():
        return build_health_response(datapaths, settings)

    @app.get("/switches")
    def switches():
        return build_switches_response(datapaths, table_miss_statuses)

    @app.get("/flow-rules")
    def flow_rules():
        return {
            "items": [
                build_flow_operation_response(status)
                for status in flow_operations.snapshot()
            ]
        }

    @app.post("/flow-rules")
    def install_flow_rule(payload: FlowRuleInstallRequest):
        try:
            dpid = parse_switch_dpid(payload.switch_id)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

        datapath = datapaths.get(dpid)
        if datapath is None:
            raise HTTPException(
                status_code=404,
                detail=f"switch is not connected: {payload.switch_id}",
            )

        rule_id = payload.rule_id.strip()
        cookie = build_external_flow_cookie(rule_id)
        try:
            flow_operations.submit(
                datapath=datapath,
                rule_id=rule_id,
                switch_id=payload.switch_id,
                cookie=cookie,
                sender=lambda: install_external_flow_with_barrier(
                    datapath,
                    rule_id=rule_id,
                    match=payload.match,
                    action=payload.action,
                    priority=payload.priority,
                    idle_timeout=payload.idle_timeout,
                    hard_timeout=payload.hard_timeout,
                    switch_link_ports=SWITCH_LINK_PORTS,
                ),
            )
        except (TypeError, ValueError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

        status = flow_operations.wait(
            rule_id,
            FLOW_CONFIRM_TIMEOUT_SECONDS,
        )
        response = build_flow_operation_response(status)
        if status.state != "installed":
            raise HTTPException(status_code=502, detail=response)
        return response

    return app


class ControllerApiServer:
    """Run Uvicorn in a native daemon thread beside OS-Ken."""

    def __init__(
        self,
        datapaths,
        table_miss_statuses,
        flow_operations,
        settings,
    ):
        config = uvicorn.Config(
            app=create_api(
                datapaths,
                table_miss_statuses,
                flow_operations,
                settings,
            ),
            host=settings.rest_host,
            port=settings.rest_port,
            log_level="warning",
            access_log=False,
            lifespan="off",
        )
        self._server = uvicorn.Server(config)
        self._thread = Thread(
            target=self._server.run,
            name="controller-rest-api",
            daemon=True,
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._server.should_exit = True
        if self._thread.is_alive():
            self._thread.join(timeout=5)

    @property
    def is_alive(self):
        return self._thread.is_alive()
