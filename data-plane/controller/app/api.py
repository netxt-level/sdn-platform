"""REST API for controller health, switches, and external Flow Rules."""

from threading import Thread

from fastapi import FastAPI
from fastapi import HTTPException
from pydantic import BaseModel
from pydantic import Field
import uvicorn

from app.flow_manager import build_external_flow_cookie
from app.flow_manager import delete_external_flow_with_barrier
from app.flow_manager import delete_rate_limit_meter
from app.flow_manager import install_external_flow_with_barrier
from app.flow_manager import install_rate_limited_flow_with_barrier
from app.flow_manager import normalize_external_match
from app.topology import SWITCH_LINK_PORTS
from app.topology import WEIGHTED_SWITCH_GRAPH
from app.topology import get_host_binding


FLOW_CONFIRM_TIMEOUT_SECONDS = 5.0


class FlowRuleInstallRequest(BaseModel):
    rule_id: str = Field(min_length=1, max_length=128)
    switch_id: str | None = Field(default=None, min_length=1, max_length=64)
    match: dict
    action: str = Field(min_length=1, max_length=64)
    priority: int = Field(ge=1, le=65535)
    idle_timeout: int | None = Field(default=None, ge=0, le=65535)
    hard_timeout: int | None = Field(default=None, ge=0, le=65535)
    rate_limit_pps: int | None = Field(default=None, ge=1)


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
    response_status = {
        "installed": "APPLIED",
        "delete_failed": "FAILED",
    }.get(status.state, status.state.upper())
    return {
        "controller_rule_id": status.rule_id,
        "switch_id": status.switch_id,
        "dpid": f"{status.dpid:016x}",
        "cookie": f"0x{status.cookie:016x}",
        "status": response_status,
        "operation": status.operation,
        "flow_xid": status.flow_xid,
        "request_xids": status.request_xids,
        "barrier_xid": status.barrier_xid,
        "meter_id": status.meter_id,
        "error": status.error,
    }


def build_topology_response(topology, hosts):
    active_graph = topology.snapshot()
    switches = [
        {
            "switch_id": f"s{dpid}",
            "dpid": f"{dpid:016x}",
            "state": "connected" if dpid in active_graph else "disconnected",
        }
        for dpid in sorted(WEIGHTED_SWITCH_GRAPH)
    ]
    links = [
        {
            "source": f"s{source}",
            "destination": f"s{destination}",
            "source_port": SWITCH_LINK_PORTS[source][destination],
            "destination_port": SWITCH_LINK_PORTS[destination][source],
            "cost": cost,
            "state": (
                "active"
                if destination in active_graph.get(source, {})
                else "inactive"
            ),
        }
        for source, neighbors in sorted(WEIGHTED_SWITCH_GRAPH.items())
        for destination, cost in sorted(neighbors.items())
        if source < destination
    ]
    learned_hosts = []
    for host in hosts.snapshot():
        binding = get_host_binding(host.dpid, host.port)
        learned_hosts.append({
            "name": None if binding is None else binding.name,
            "mac": host.mac,
            "ipv4": host.ipv4,
            "switch_id": f"s{host.dpid}",
            "port": host.port,
        })
    return {
        "switches": switches,
        "links": links,
        "hosts": learned_hosts,
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


def create_api(
    datapaths,
    table_miss_statuses,
    flow_operations,
    meters,
    hosts,
    topology,
    path_recalculator,
    settings,
):
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

    @app.get("/meters")
    def meter_list():
        return {
            "items": list(meters.snapshot()),
        }

    @app.get("/topology")
    def topology_snapshot():
        return build_topology_response(topology, hosts)

    @app.post("/paths/recalculate")
    def recalculate_paths():
        invalidated_switches = path_recalculator(
            "controller_api_request",
        )
        return {
            "status": "RECALCULATED",
            "invalidated_switches": invalidated_switches,
            "topology": build_topology_response(topology, hosts),
        }

    @app.post("/flow-rules")
    def install_flow_rule(payload: FlowRuleInstallRequest):
        if payload.switch_id is None:
            source_ipv4 = payload.match.get("ipv4_src")
            try:
                host = hosts.get_by_ipv4(source_ipv4)
            except ValueError as error:
                raise HTTPException(
                    status_code=422,
                    detail="switch_id or a valid learned ipv4_src is required",
                ) from error
            if host is None:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "switch_id is missing and source host has not been "
                        f"learned: {source_ipv4}"
                    ),
                )
            dpid = host.dpid
            resolved_switch_id = f"s{dpid}"
        else:
            try:
                dpid = parse_switch_dpid(payload.switch_id)
            except ValueError as error:
                raise HTTPException(
                    status_code=422,
                    detail=str(error),
                ) from error
            resolved_switch_id = payload.switch_id

        datapath = datapaths.get(dpid)
        if datapath is None:
            raise HTTPException(
                status_code=404,
                detail=f"switch is not connected: {resolved_switch_id}",
            )

        rule_id = payload.rule_id.strip()
        cookie = build_external_flow_cookie(rule_id)
        meter_lease = None
        try:
            normalize_external_match(payload.match)
            if payload.action.strip().upper() == "RATE_LIMIT":
                if payload.rate_limit_pps is None:
                    raise ValueError(
                        "RATE_LIMIT requires rate_limit_pps"
                    )
                meter_lease = meters.allocate(
                    dpid,
                    rule_id,
                    payload.rate_limit_pps,
                )
                sender = lambda: install_rate_limited_flow_with_barrier(
                    datapath,
                    meter_id=meter_lease.meter_id,
                    rate_limit_pps=meter_lease.rate_limit_pps,
                    install_meter=meter_lease.created,
                    rule_id=rule_id,
                    match=payload.match,
                    action=payload.action,
                    priority=payload.priority,
                    idle_timeout=payload.idle_timeout,
                    hard_timeout=payload.hard_timeout,
                    switch_link_ports=SWITCH_LINK_PORTS,
                )
            else:
                sender = lambda: install_external_flow_with_barrier(
                    datapath,
                    rule_id=rule_id,
                    match=payload.match,
                    action=payload.action,
                    priority=payload.priority,
                    idle_timeout=payload.idle_timeout,
                    hard_timeout=payload.hard_timeout,
                    switch_link_ports=SWITCH_LINK_PORTS,
                )
            flow_operations.submit(
                datapath=datapath,
                rule_id=rule_id,
                switch_id=resolved_switch_id,
                cookie=cookie,
                sender=sender,
                meter_id=(
                    None if meter_lease is None else meter_lease.meter_id
                ),
            )
        except (TypeError, ValueError) as error:
            if meter_lease is not None:
                unused_meter_id = meters.release(dpid, rule_id)
                if unused_meter_id is not None:
                    delete_rate_limit_meter(datapath, unused_meter_id)
            raise HTTPException(status_code=422, detail=str(error)) from error

        status = flow_operations.wait(
            rule_id,
            FLOW_CONFIRM_TIMEOUT_SECONDS,
        )
        response = build_flow_operation_response(status)
        if status.state != "installed":
            if meter_lease is not None:
                unused_meter_id = meters.release(dpid, rule_id)
                if unused_meter_id is not None:
                    delete_rate_limit_meter(datapath, unused_meter_id)
            raise HTTPException(status_code=502, detail=response)
        return response

    @app.delete("/flow-rules/{rule_id}")
    def delete_flow_rule(
        rule_id: str,
        switch_id: str | None = None,
    ):
        normalized_rule_id = rule_id.strip()
        if not normalized_rule_id:
            raise HTTPException(
                status_code=422,
                detail="rule_id must be a non-empty string",
            )

        existing = flow_operations.get(normalized_rule_id)
        if existing is not None and existing.state == "removed":
            return build_flow_operation_response(existing)

        if existing is not None:
            dpid = existing.dpid
            resolved_switch_id = existing.switch_id
            if switch_id is not None:
                try:
                    requested_dpid = parse_switch_dpid(switch_id)
                except ValueError as error:
                    raise HTTPException(
                        status_code=422,
                        detail=str(error),
                    ) from error
                if requested_dpid != dpid:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"rule belongs to {resolved_switch_id}, "
                            f"not {switch_id}"
                        ),
                    )
        else:
            if switch_id is None:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        "Flow Rule is not tracked; switch_id is required "
                        "for cookie-based cleanup"
                    ),
                )
            try:
                dpid = parse_switch_dpid(switch_id)
            except ValueError as error:
                raise HTTPException(
                    status_code=422,
                    detail=str(error),
                ) from error
            resolved_switch_id = switch_id

        datapath = datapaths.get(dpid)
        if datapath is None:
            raise HTTPException(
                status_code=404,
                detail=f"switch is not connected: {resolved_switch_id}",
            )

        try:
            flow_operations.submit_removal(
                datapath=datapath,
                rule_id=normalized_rule_id,
                switch_id=resolved_switch_id,
                cookie=build_external_flow_cookie(normalized_rule_id),
                sender=lambda: delete_external_flow_with_barrier(
                    datapath,
                    normalized_rule_id,
                ),
            )
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

        status = flow_operations.wait(
            normalized_rule_id,
            FLOW_CONFIRM_TIMEOUT_SECONDS,
        )
        response = build_flow_operation_response(status)
        if status.state != "removed":
            raise HTTPException(status_code=502, detail=response)

        unused_meter_id = meters.release(dpid, normalized_rule_id)
        if unused_meter_id is not None:
            delete_rate_limit_meter(datapath, unused_meter_id)
        response["meter_removed"] = unused_meter_id
        return response

    return app


class ControllerApiServer:
    """Run Uvicorn in a native daemon thread beside OS-Ken."""

    def __init__(
        self,
        datapaths,
        table_miss_statuses,
        flow_operations,
        meters,
        hosts,
        topology,
        path_recalculator,
        settings,
    ):
        config = uvicorn.Config(
            app=create_api(
                datapaths,
                table_miss_statuses,
                flow_operations,
                meters,
                hosts,
                topology,
                path_recalculator,
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
