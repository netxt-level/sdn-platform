from __future__ import annotations

from typing import Any

from app.repositories.flow_repository import FlowRepository
from app.services.dashboard_service import DashboardService
from app.clients.controller import ControllerClient
from app.clients.controller import ControllerClientError
from app.core.config import settings
from app.services.switch_utilization import SwitchUtilizationTracker


LINK_DEFINITIONS = (
    ("s1-s2", "s1", "s2", "primary"),
    ("s2-s4", "s2", "s4", "primary"),
    ("s1-s3", "s1", "s3", "backup"),
    ("s3-s4", "s3", "s4", "backup"),
)


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
                self._edge_key(link.get("source"), link.get("destination"))
                for link in topology.get("links", [])
                if link.get("state") == "active"
            }
            if not {
                self._edge_key("s1", "s2"),
                self._edge_key("s2", "s4"),
            }.issubset(active_links):
                active_path = "backup"
        except ControllerClientError:
            pass

        primary_nodes = ["s1", "s2", "s4"]
        backup_nodes = ["s1", "s3", "s4"]
        topology_links = self._topology_link_map(topology)
        port_usage = self._port_usage_map(switches)
        links = [
            self._link_status(
                link_id,
                source,
                target,
                path,
                selected=active_path == path,
                topology_link=topology_links.get(
                    self._edge_key(source, target)
                ),
                port_usage=port_usage,
            )
            for link_id, source, target, path in LINK_DEFINITIONS
        ]
        primary_utilization = self._path_utilization("primary", links)
        backup_utilization = self._path_utilization("backup", links)

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
            "links": links,
            "switches": switches,
            "utilization_source": "openflow_port_counter_delta",
            "history": [self._history_item(rule) for rule in flow_rules[:8]],
            "controller": controller_state,
        }

    @staticmethod
    def _path_utilization(
        path: str,
        links: list[dict[str, Any]],
    ) -> float:
        return round(
            max(
                (
                    float(link["utilization"])
                    for link in links
                    if link["path"] == path
                ),
                default=0.0,
            ),
            2,
        )

    @staticmethod
    def _edge_key(source: Any, target: Any) -> tuple[str, str]:
        return tuple(sorted((str(source), str(target))))

    @classmethod
    def _topology_link_map(
        cls,
        topology: dict[str, Any],
    ) -> dict[tuple[str, str], dict[str, Any]]:
        return {
            cls._edge_key(link.get("source"), link.get("destination")): link
            for link in topology.get("links", [])
            if link.get("source") and link.get("destination")
        }

    @staticmethod
    def _port_usage_map(
        switches: list[dict[str, Any]],
    ) -> dict[tuple[str, int], dict[str, Any]]:
        return {
            (str(switch["switch_id"]), int(port["port_no"])): port
            for switch in switches
            for port in switch.get("ports", [])
        }

    @classmethod
    def _link_status(
        cls,
        link_id: str,
        source: str,
        target: str,
        path: str,
        *,
        selected: bool,
        topology_link: dict[str, Any] | None,
        port_usage: dict[tuple[str, int], dict[str, Any]],
    ) -> dict[str, Any]:
        state = (
            str(topology_link.get("state", "unknown"))
            if topology_link
            else "unknown"
        )
        source_port = None
        target_port = None
        if topology_link:
            if topology_link.get("source") == source:
                source_port = topology_link.get("source_port")
                target_port = topology_link.get("destination_port")
            else:
                source_port = topology_link.get("destination_port")
                target_port = topology_link.get("source_port")

        samples = [
            port_usage.get((source, int(source_port)))
            if source_port is not None
            else None,
            port_usage.get((target, int(target_port)))
            if target_port is not None
            else None,
        ]
        samples = [sample for sample in samples if sample is not None]

        return {
            "id": link_id,
            "source": source,
            "target": target,
            "source_port": source_port,
            "target_port": target_port,
            "path": path,
            "state": state,
            "selected": selected,
            "active": state == "active",
            "bps": round(
                max((float(item["bps"]) for item in samples), default=0.0),
                2,
            ),
            "rx_bps": round(
                max((float(item["rx_bps"]) for item in samples), default=0.0),
                2,
            ),
            "tx_bps": round(
                max((float(item["tx_bps"]) for item in samples), default=0.0),
                2,
            ),
            "utilization": round(
                max(
                    (float(item["utilization"]) for item in samples),
                    default=0.0,
                ),
                2,
            ),
            "capacity_bps": max(
                (int(item["capacity_bps"]) for item in samples),
                default=settings.switch_port_capacity_bps,
            ),
            "sampled": any(bool(item.get("sampled")) for item in samples),
        }

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
