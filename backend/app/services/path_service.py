from __future__ import annotations

from typing import Any

from app.repositories.flow_repository import FlowRepository
from app.repositories.platform_settings_repository import PlatformSettingsRepository
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
        platform_settings_repository: PlatformSettingsRepository | None = None,
    ):
        self.dashboard_service = dashboard_service or DashboardService()
        self.flow_repository = flow_repository or FlowRepository()
        self.controller_client = controller_client or ControllerClient()
        self.utilization_tracker = (
            utilization_tracker
            or SwitchUtilizationTracker(
                settings.switch_port_capacity_bps,
                settings.path_capacity_pps,
            )
        )
        self.platform_settings_repository = (
            platform_settings_repository or PlatformSettingsRepository()
        )

    def get_status(self) -> dict[str, Any]:
        summary = self.dashboard_service.get_summary()
        flow_rules = self.flow_repository.list_flows()
        threshold = int(
            self.platform_settings_repository.get()[
                "congestion_threshold_percent"
            ]
        )
        active_path = "primary"
        distribution_mode = "primary"
        path_capacity_pps = settings.path_capacity_pps
        distribution_threshold_pps = settings.path_distribution_threshold_pps
        distribution_recovery_pps = settings.path_distribution_recovery_pps
        controller_manages_distribution = False
        controller_state = None
        switches = []
        topology = {"links": [], "switches": []}
        try:
            topology = self.controller_client.get_topology()
            stats = self.controller_client.get_stats()
            controller_state = {"topology": topology, "stats": stats}
            switches = self.utilization_tracker.update(stats, topology)
            active_path = self._reported_active_path(topology)
            distribution = stats.get("path_distribution")
            if isinstance(distribution, dict):
                controller_manages_distribution = True
                distribution_mode = str(
                    distribution.get("mode") or "primary"
                )
                distribution_threshold_pps = int(
                    distribution.get("threshold_pps")
                    or distribution_threshold_pps
                )
                distribution_recovery_pps = int(
                    distribution.get("recovery_pps")
                    if distribution.get("recovery_pps") is not None
                    else distribution_recovery_pps
                )
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
                selected=(
                    distribution_mode == "balanced"
                    or active_path == path
                ),
                topology_link=topology_links.get(
                    self._edge_key(source, target)
                ),
                port_usage=port_usage,
            )
            for link_id, source, target, path in LINK_DEFINITIONS
        ]
        primary_utilization = self._path_utilization("primary", links)
        backup_utilization = self._path_utilization("backup", links)
        primary_pps = self._path_pps("primary", links)
        backup_pps = self._path_pps("backup", links)
        if controller_state is not None and not controller_manages_distribution:
            desired_path = self._desired_active_path(
                active_path,
                links,
                threshold,
            )
            if desired_path != active_path:
                try:
                    control_response = self.controller_client.recalculate_paths(
                        desired_path,
                    )
                    controller_state["path_control"] = control_response
                    active_path = desired_path
                    for link in links:
                        link["selected"] = link["path"] == active_path
                except ControllerClientError as error:
                    controller_state["path_control_error"] = str(error)

        return {
            "active_path": active_path,
            "network_status": summary.get("network_status", "normal"),
            "paths": {
                "primary": {
                    "name": "primary",
                    "nodes": primary_nodes,
                    "utilization": primary_utilization,
                    "pps": primary_pps,
                    "pps_utilization": self._pps_utilization(
                        primary_pps,
                        path_capacity_pps,
                    ),
                    "active": (
                        distribution_mode == "balanced"
                        or active_path == "primary"
                    ),
                },
                "backup": {
                    "name": "backup",
                    "nodes": backup_nodes,
                    "utilization": backup_utilization,
                    "pps": backup_pps,
                    "pps_utilization": self._pps_utilization(
                        backup_pps,
                        path_capacity_pps,
                    ),
                    "active": (
                        distribution_mode == "balanced"
                        or active_path == "backup"
                    ),
                },
            },
            "links": links,
            "switches": switches,
            "utilization_source": "openflow_port_counter_delta",
            "congestion_threshold_percent": threshold,
            "path_distribution_mode": distribution_mode,
            "path_capacity_pps": path_capacity_pps,
            "path_distribution_threshold_pps": distribution_threshold_pps,
            "path_distribution_recovery_pps": distribution_recovery_pps,
            "history": [self._history_item(rule) for rule in flow_rules[:8]],
            "controller": controller_state,
        }

    @staticmethod
    def _path_pps(
        path: str,
        links: list[dict[str, Any]],
    ) -> float:
        return round(
            max(
                (
                    float(link["pps"])
                    for link in links
                    if link["path"] == path
                ),
                default=0.0,
            ),
            2,
        )

    @staticmethod
    def _pps_utilization(pps: float, threshold_pps: int) -> float:
        if threshold_pps <= 0:
            return 0.0
        return round(pps / threshold_pps * 100, 2)

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
            "pps": round(
                max((float(item["pps"]) for item in samples), default=0.0),
                2,
            ),
            "rx_pps": round(
                max((float(item["rx_pps"]) for item in samples), default=0.0),
                2,
            ),
            "tx_pps": round(
                max((float(item["tx_pps"]) for item in samples), default=0.0),
                2,
            ),
            "pps_utilization": round(
                max(
                    (
                        float(item["pps_utilization"])
                        for item in samples
                    ),
                    default=0.0,
                ),
                2,
            ),
            "capacity_pps": max(
                (int(item["capacity_pps"]) for item in samples),
                default=settings.path_capacity_pps,
            ),
            "sampled": any(bool(item.get("sampled")) for item in samples),
        }

    @classmethod
    def _reported_active_path(cls, topology: dict[str, Any]) -> str:
        links = cls._topology_link_map(topology)
        path_edges = {
            "primary": (("s1", "s2"), ("s2", "s4")),
            "backup": (("s1", "s3"), ("s3", "s4")),
        }
        available = {
            path: all(
                links.get(cls._edge_key(*edge), {}).get("state") == "active"
                for edge in edges
            )
            for path, edges in path_edges.items()
        }
        if not available["primary"] and available["backup"]:
            return "backup"
        if not available["backup"]:
            return "primary"

        costs = {
            path: sum(
                float(links.get(cls._edge_key(*edge), {}).get("cost") or 1)
                for edge in edges
            )
            for path, edges in path_edges.items()
        }
        return "primary" if costs["primary"] <= costs["backup"] else "backup"

    @staticmethod
    def _desired_active_path(
        current_path: str,
        links: list[dict[str, Any]],
        threshold: int,
    ) -> str:
        by_path = {
            path: [link for link in links if link["path"] == path]
            for path in ("primary", "backup")
        }
        available = {
            path: bool(path_links)
            and all(link["state"] == "active" for link in path_links)
            for path, path_links in by_path.items()
        }
        if not available[current_path]:
            alternate = "backup" if current_path == "primary" else "primary"
            return alternate if available[alternate] else current_path

        utilization = {
            path: max(
                (float(link["utilization"]) for link in path_links),
                default=0.0,
            )
            for path, path_links in by_path.items()
        }
        if (
            current_path == "primary"
            and available["backup"]
            and utilization["primary"] >= threshold
            and utilization["backup"] < utilization["primary"]
        ):
            return "backup"
        if (
            current_path == "backup"
            and available["primary"]
            and utilization["primary"] <= max(0, threshold - 10)
            and utilization["backup"] <= max(0, threshold - 10)
        ):
            return "primary"
        return current_path

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
