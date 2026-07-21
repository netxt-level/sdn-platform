from __future__ import annotations

from typing import Any

from app.repositories.flow_repository import FlowRepository
from app.services.dashboard_service import DashboardService
from app.clients.controller import ControllerClient
from app.clients.controller import ControllerClientError
from app.core.config import settings
from app.services.switch_utilization import SwitchUtilizationTracker


class PathService:
    def __init__(
        self,
        dashboard_service: DashboardService | None = None,
        flow_repository: FlowRepository | None = None,
        controller_client: ControllerClient | None = None,
        utilization_tracker: SwitchUtilizationTracker | None = None,
    ):
        self.dashboard_service = dashboard_service or DashboardService()
        self.flow_repository = flow_repository or FlowRepository()
        self.controller_client = controller_client or ControllerClient()
        self.utilization_tracker = (
            utilization_tracker
            or SwitchUtilizationTracker(settings.switch_port_capacity_bps)
        )

    def get_status(self) -> dict[str, Any]:
        summary = self.dashboard_service.get_summary()
        flow_rules = self.flow_repository.list_flows()
        active_path = self._decide_active_path(summary, flow_rules)
        controller_state = None
        switches = []
        topology = {"links": [], "switches": []}
        try:
            topology = self.controller_client.get_topology()
            stats = self.controller_client.get_stats()
            controller_state = {"topology": topology, "stats": stats}
            switches = self.utilization_tracker.update(stats, topology)
            active_links = {
                (link.get("source"), link.get("destination"))
                for link in topology.get("links", [])
                if link.get("state") == "active"
            }
            if not {
                ("s1", "s2"),
                ("s2", "s4"),
            }.issubset(active_links):
                active_path = "backup"
        except ControllerClientError:
            pass

        utilization_by_switch = {
            item["switch_id"]: float(item["utilization"])
            for item in switches
        }
        primary_nodes = ["s1", "s2", "s4"]
        backup_nodes = ["s1", "s3", "s4"]
        primary_utilization = self._path_utilization(
            primary_nodes,
            utilization_by_switch,
        )
        backup_utilization = self._path_utilization(
            backup_nodes,
            utilization_by_switch,
        )

        return {
            "active_path": active_path,
            "network_status": summary.get("network_status", "normal"),
            "paths": {
                "primary": {
                    "name": "primary",
                    "nodes": primary_nodes,
                    "utilization": primary_utilization,
                    "active": active_path == "primary",
                },
                "backup": {
                    "name": "backup",
                    "nodes": backup_nodes,
                    "utilization": backup_utilization,
                    "active": active_path == "backup",
                },
            },
            "links": [
                {
                    "id": "s1-s2",
                    "source": "s1",
                    "target": "s2",
                    "path": "primary",
                    "active": active_path == "primary",
                    "utilization": self._link_utilization(
                        "s1", "s2", utilization_by_switch
                    ),
                },
                {
                    "id": "s2-s4",
                    "source": "s2",
                    "target": "s4",
                    "path": "primary",
                    "active": active_path == "primary",
                    "utilization": self._link_utilization(
                        "s2", "s4", utilization_by_switch
                    ),
                },
                {
                    "id": "s1-s3",
                    "source": "s1",
                    "target": "s3",
                    "path": "backup",
                    "active": active_path == "backup",
                    "utilization": self._link_utilization(
                        "s1", "s3", utilization_by_switch
                    ),
                },
                {
                    "id": "s3-s4",
                    "source": "s3",
                    "target": "s4",
                    "path": "backup",
                    "active": active_path == "backup",
                    "utilization": self._link_utilization(
                        "s3", "s4", utilization_by_switch
                    ),
                },
            ],
            "switches": switches,
            "utilization_source": "openflow_port_counter_delta",
            "history": [self._history_item(rule) for rule in flow_rules[:8]],
            "controller": controller_state,
        }

    @staticmethod
    def _path_utilization(
        nodes: list[str],
        utilization_by_switch: dict[str, float],
    ) -> float:
        return round(
            max(
                (utilization_by_switch.get(node, 0.0) for node in nodes),
                default=0.0,
            ),
            2,
        )

    @staticmethod
    def _link_utilization(
        source: str,
        target: str,
        utilization_by_switch: dict[str, float],
    ) -> float:
        return round(
            max(
                utilization_by_switch.get(source, 0.0),
                utilization_by_switch.get(target, 0.0),
            ),
            2,
        )

    def _decide_active_path(
        self,
        summary: dict[str, Any],
        flow_rules: list[dict[str, Any]],
    ) -> str:
        if summary.get("network_status") == "critical":
            return "backup"

        # 컨트롤러 적용 전에는 PENDING 대응 후보를 우회 필요 신호로 간주한다.
        has_pending_response = any(
            str(rule.get("status", "")).upper() == "PENDING"
            and str(rule.get("action", "")).upper() in {"RATE_LIMIT", "DROP"}
            for rule in flow_rules
        )

        return "backup" if has_pending_response else "primary"

    def _history_item(self, rule: dict[str, Any]) -> dict[str, Any]:
        action = str(rule.get("action") or "-")
        src = rule.get("src_ip") or rule.get("match", {}).get("ipv4_src")
        dst = rule.get("dst_ip") or rule.get("match", {}).get("ipv4_dst")
        reason = (
            f"{rule['source_event_id']} 대응"
            if rule.get("source_event_id")
            else f"{src or '*'} → {dst or '*'}"
        )

        return {
            "id": rule["id"],
            "time": rule.get("created_at") or rule.get("timestamp"),
            "from": "primary",
            "to": action,
            "reason": reason,
            "status": rule.get("status", "UNKNOWN"),
        }
