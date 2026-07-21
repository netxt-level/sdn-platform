from datetime import datetime
from datetime import timezone

from app.clients.controller import ControllerClient
from app.clients.controller import ControllerClientError
from app.repositories.flow_repository import FlowRepository


class FlowRuleNotFoundError(LookupError):
    pass


class FlowService:
    def __init__(
        self,
        flow_repository: FlowRepository | None = None,
        controller_client: ControllerClient | None = None,
    ):
        self.flow_repository = flow_repository or FlowRepository()
        self.controller_client = controller_client or ControllerClient()

    def get_flows(self, src_ip: str | None = None) -> dict:
        flow_rules = self.flow_repository.list_flows(src_ip)
        try:
            topology = self.controller_client.get_topology()
            stats = self.controller_client.get_stats()
        except ControllerClientError as error:
            return {
                "items": flow_rules,
                "total": len(flow_rules),
                "controller": {
                    "available": False,
                    "updated_at": None,
                    "switches": [],
                    "links": [],
                    "error": str(error),
                },
            }

        counters = self._flow_counters_by_cookie(stats)
        items = []
        for flow_rule in flow_rules:
            controller_response = flow_rule.get("controller_response") or {}
            counter = counters.get((
                flow_rule.get("switch_id"),
                controller_response.get("cookie"),
            ))
            items.append({
                **flow_rule,
                "packet_count": (
                    None if counter is None else counter["packet_count"]
                ),
                "byte_count": (
                    None if counter is None else counter["byte_count"]
                ),
            })

        return {
            "items": items,
            "total": len(items),
            "controller": {
                "available": True,
                "updated_at": stats.get("updated_at"),
                "switches": topology.get("switches", []),
                "links": topology.get("links", []),
                "error": None,
            },
        }

    @staticmethod
    def _flow_counters_by_cookie(stats: dict) -> dict:
        counters = {}
        for switch in stats.get("switches", []):
            switch_id = switch.get("switch_id")
            for flow in switch.get("flows", []):
                cookie = flow.get("cookie")
                if not switch_id or not cookie:
                    continue
                key = (switch_id, cookie)
                current = counters.get(key)
                candidate = {
                    "packet_count": int(flow.get("packet_count") or 0),
                    "byte_count": int(flow.get("byte_count") or 0),
                }
                # 동일 cookie가 여러 table에 존재해도 패킷을 중복 합산하지 않는다.
                if current is None:
                    counters[key] = candidate
                else:
                    counters[key] = {
                        "packet_count": max(
                            current["packet_count"],
                            candidate["packet_count"],
                        ),
                        "byte_count": max(
                            current["byte_count"],
                            candidate["byte_count"],
                        ),
                    }
        return counters

    def create_flow(self, data: dict) -> dict:
        flow_rule = self.flow_repository.create_manual_flow(
            switch_id=data.get("switch_id"),
            match=data["match"],
            action=data["action"],
            priority=data["priority"],
            idle_timeout=data.get("idle_timeout"),
            hard_timeout=data.get("hard_timeout"),
            rate_limit_pps=data.get("rate_limit_pps"),
        )
        return self.apply_flow(flow_rule)

    def apply_flow(self, flow_rule: dict, *, force: bool = False) -> dict:
        if not force and flow_rule.get("status") in {
            "APPLIED",
            "APPLYING",
            "REMOVING",
            "REMOVED",
            "EXPIRED",
            "REMOVE_FAILED",
        }:
            return flow_rule

        requested_at = datetime.now(timezone.utc)
        applying = self.flow_repository.update_status(
            flow_rule["id"],
            status="APPLYING",
            requested_at=requested_at,
        )

        try:
            controller_response = self.controller_client.install_flow_rule(
                applying or flow_rule
            )
        except ControllerClientError as error:
            return self.flow_repository.update_status(
                flow_rule["id"],
                status="FAILED",
                controller_response=error.response,
                error_message=str(error),
                requested_at=requested_at,
            )

        return self.flow_repository.update_status(
            flow_rule["id"],
            status="APPLIED",
            controller_rule_id=controller_response["controller_rule_id"],
            controller_response=controller_response,
            switch_id=controller_response.get("switch_id"),
            requested_at=requested_at,
            applied_at=datetime.now(timezone.utc),
        )

    def delete_flow(self, flow_rule_id: str) -> dict:
        flow_rule = self.flow_repository.get_flow(flow_rule_id)
        if flow_rule is None:
            raise FlowRuleNotFoundError(flow_rule_id)
        if flow_rule.get("status") == "REMOVED":
            return flow_rule
        if flow_rule.get("status") == "APPLYING":
            raise RuntimeError(
                "Flow Rule installation is still in progress"
            )

        requested_at = datetime.now(timezone.utc)
        removing = self.flow_repository.update_status(
            flow_rule_id,
            status="REMOVING",
            controller_rule_id=flow_rule.get("controller_rule_id"),
            controller_response=flow_rule.get("controller_response"),
            switch_id=flow_rule.get("switch_id"),
            requested_at=requested_at,
            applied_at=flow_rule.get("applied_at"),
        )

        try:
            controller_response = self.controller_client.delete_flow_rule(
                removing or flow_rule
            )
        except ControllerClientError as error:
            return self.flow_repository.update_status(
                flow_rule_id,
                status="REMOVE_FAILED",
                controller_rule_id=flow_rule.get("controller_rule_id"),
                controller_response=error.response,
                switch_id=flow_rule.get("switch_id"),
                error_message=str(error),
                requested_at=requested_at,
                applied_at=flow_rule.get("applied_at"),
            )

        return self.flow_repository.update_status(
            flow_rule_id,
            status="REMOVED",
            controller_rule_id=controller_response["controller_rule_id"],
            controller_response=controller_response,
            switch_id=(
                controller_response.get("switch_id")
                or flow_rule.get("switch_id")
            ),
            requested_at=requested_at,
            applied_at=flow_rule.get("applied_at"),
            removed_at=datetime.now(timezone.utc),
        )

    def reconcile_flows(self) -> dict:
        try:
            controller_rules = self.controller_client.list_flow_rules()
        except ControllerClientError as error:
            return {
                "status": "FAILED",
                "checked": 0,
                "updated": 0,
                "reapplied": 0,
                "error": str(error),
            }

        controller_by_id = {
            item.get("controller_rule_id"): item
            for item in controller_rules
            if item.get("controller_rule_id")
        }
        backend_rules = self.flow_repository.list_flows()
        updated = 0
        reapplied = 0
        failures = []

        for flow_rule in backend_rules:
            backend_status = flow_rule.get("status")
            if backend_status in {"REMOVING", "REMOVE_FAILED"}:
                result = self.delete_flow(flow_rule["id"])
                if result.get("status") == "REMOVED":
                    updated += 1
                else:
                    failures.append({
                        "flow_rule_id": flow_rule["id"],
                        "error": result.get("error_message"),
                    })
                continue
            if backend_status not in {
                "PENDING",
                "FAILED",
                "APPLIED",
                "APPLYING",
            }:
                continue
            controller_rule = controller_by_id.get(flow_rule["id"])
            controller_status = (
                None if controller_rule is None else controller_rule.get("status")
            )
            if controller_status in {"EXPIRED", "REMOVED"}:
                completed_at = datetime.now(timezone.utc)
                self.flow_repository.update_status(
                    flow_rule["id"],
                    status=controller_status,
                    controller_rule_id=flow_rule.get("controller_rule_id"),
                    controller_response=controller_rule,
                    switch_id=flow_rule.get("switch_id"),
                    requested_at=flow_rule.get("requested_at"),
                    applied_at=flow_rule.get("applied_at"),
                    removed_at=completed_at,
                )
                updated += 1
                continue
            if controller_status == "APPLIED":
                if backend_status != "APPLIED":
                    self.flow_repository.update_status(
                        flow_rule["id"],
                        status="APPLIED",
                        controller_rule_id=flow_rule["id"],
                        controller_response=controller_rule,
                        switch_id=(
                            controller_rule.get("switch_id")
                            or flow_rule.get("switch_id")
                        ),
                        requested_at=flow_rule.get("requested_at"),
                        applied_at=(
                            flow_rule.get("applied_at")
                            or datetime.now(timezone.utc)
                        ),
                    )
                    updated += 1
                continue

            result = self.apply_flow(flow_rule, force=True)
            if result.get("status") == "APPLIED":
                reapplied += 1
            else:
                failures.append({
                    "flow_rule_id": flow_rule["id"],
                    "error": result.get("error_message"),
                })

        return {
            "status": "COMPLETED" if not failures else "PARTIAL",
            "checked": len(backend_rules),
            "updated": updated,
            "reapplied": reapplied,
            "failures": failures,
        }
