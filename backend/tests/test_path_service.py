import sys
import types


class Dashboard:
    def get_summary(self):
        return {"current_bps": 0, "network_status": "normal"}


class Flows:
    def list_flows(self):
        return []


class RuntimeSettings:
    def __init__(self, threshold=70):
        self.threshold = threshold

    def get(self):
        return {
            "congestion_threshold_percent": self.threshold,
            "automatic_response_enabled": True,
        }


class Controller:
    def get_topology(self):
        return {
            "switches": [
                {"switch_id": "s1", "state": "connected"},
                {"switch_id": "s2", "state": "connected"},
                {"switch_id": "s3", "state": "connected"},
                {"switch_id": "s4", "state": "connected"},
            ],
            "links": [
                {
                    "source": "s1",
                    "destination": "s2",
                    "source_port": 4,
                    "destination_port": 1,
                    "state": "inactive",
                },
                {
                    "source": "s2",
                    "destination": "s4",
                    "source_port": 2,
                    "destination_port": 1,
                    "state": "inactive",
                },
                {
                    "source": "s1",
                    "destination": "s3",
                    "source_port": 5,
                    "destination_port": 1,
                    "state": "active",
                },
                {
                    "source": "s3",
                    "destination": "s4",
                    "source_port": 2,
                    "destination_port": 2,
                    "state": "active",
                },
            ],
        }

    def get_stats(self):
        return {"switches": [{"switch_id": "s1"}]}


class Utilization:
    def update(self, stats, topology):
        return [
            {
                "switch_id": "s1",
                "utilization": 99.0,
                "ports": [
                    port_usage(4, 1_000_000, 10.0),
                    port_usage(5, 2_000_000, 20.0),
                ],
            },
            {
                "switch_id": "s2",
                "utilization": 40.0,
                "ports": [
                    port_usage(1, 1_000_000, 10.0),
                    port_usage(2, 4_000_000, 40.0),
                ],
            },
            {
                "switch_id": "s3",
                "utilization": 30.0,
                "ports": [
                    port_usage(1, 2_000_000, 20.0),
                    port_usage(2, 3_000_000, 30.0),
                ],
            },
            {
                "switch_id": "s4",
                "utilization": 50.0,
                "ports": [
                    port_usage(1, 4_000_000, 40.0),
                    port_usage(2, 3_000_000, 30.0),
                ],
            },
        ]


def port_usage(port_no, bps, utilization):
    return {
        "port_no": port_no,
        "bps": bps,
        "rx_bps": bps,
        "tx_bps": bps / 2,
        "utilization": utilization,
        "capacity_bps": 10_000_000,
        "pps": bps / 10_000,
        "rx_pps": bps / 10_000,
        "tx_pps": bps / 20_000,
        "pps_utilization": bps / 100_000,
        "capacity_pps": 1000,
        "sampled": True,
    }


def test_path_status_uses_actual_controller_topology(load_service_module):
    controller_module = types.ModuleType("app.clients.controller")
    controller_module.ControllerClient = Controller
    controller_module.ControllerClientError = RuntimeError
    sys.modules["app.clients.controller"] = controller_module
    module = load_service_module(
        "path_service",
        stubs={
            "app.repositories.flow_repository": {"FlowRepository": Flows},
            "app.repositories.platform_settings_repository": {
                "PlatformSettingsRepository": RuntimeSettings,
            },
            "app.services.dashboard_service": {"DashboardService": Dashboard},
        },
    )
    service = module.PathService(
        Dashboard(),
        Flows(),
        Controller(),
        platform_settings_repository=RuntimeSettings(),
    )

    result = service.get_status()

    assert result["active_path"] == "backup"
    assert result["controller"]["stats"]["switches"][0]["switch_id"] == "s1"
    assert result["links"][0]["state"] == "inactive"
    assert result["links"][0]["selected"] is False
    assert result["links"][2]["state"] == "active"
    assert result["links"][2]["selected"] is True


def test_path_status_uses_switch_counter_utilization(load_service_module):
    controller_module = types.ModuleType("app.clients.controller")
    controller_module.ControllerClient = Controller
    controller_module.ControllerClientError = RuntimeError
    sys.modules["app.clients.controller"] = controller_module
    module = load_service_module(
        "path_service",
        stubs={
            "app.repositories.flow_repository": {"FlowRepository": Flows},
            "app.repositories.platform_settings_repository": {
                "PlatformSettingsRepository": RuntimeSettings,
            },
            "app.services.dashboard_service": {"DashboardService": Dashboard},
        },
    )
    service = module.PathService(
        Dashboard(),
        Flows(),
        Controller(),
        Utilization(),
        RuntimeSettings(),
    )

    result = service.get_status()

    assert result["utilization_source"] == "openflow_port_counter_delta"
    assert result["switches"][1]["switch_id"] == "s2"
    assert result["paths"]["primary"]["utilization"] == 40.0
    assert result["paths"]["backup"]["utilization"] == 30.0
    assert result["links"][0]["utilization"] == 10.0
    assert result["links"][0]["bps"] == 1_000_000
    assert result["paths"]["primary"]["pps"] == 400.0
    assert result["paths"]["backup"]["pps"] == 300.0
    assert result["paths"]["primary"]["pps_utilization"] == 40.0
    assert result["paths"]["backup"]["pps_utilization"] == 30.0
    assert result["links"][2]["utilization"] == 20.0


class ActiveController(Controller):
    def __init__(self):
        self.recalculations = []

    def get_topology(self):
        topology = super().get_topology()
        for link in topology["links"]:
            link["state"] = "active"
            link["cost"] = 1 if link["destination"] in {"s2", "s4"} and link["source"] != "s3" else 10
        return topology

    def recalculate_paths(self, preferred_path):
        self.recalculations.append(preferred_path)
        return {"status": "RECALCULATED", "preferred_path": preferred_path}


class CongestedUtilization(Utilization):
    def update(self, stats, topology):
        switches = super().update(stats, topology)
        for switch in switches:
            for port in switch["ports"]:
                if (switch["switch_id"], port["port_no"]) in {
                    ("s1", 4), ("s2", 1), ("s2", 2), ("s4", 1)
                }:
                    port["utilization"] = 85.0
                else:
                    port["utilization"] = 20.0
        return switches


class DistributedController(ActiveController):
    def get_stats(self):
        return {
            "path_distribution": {
                "mode": "balanced",
                "pps": 850.0,
                "threshold_pps": 800.0,
                "recovery_pps": 600.0,
            },
            "switches": [{"switch_id": "s1"}],
        }


def test_congestion_requests_actual_backup_path_recalculation(load_service_module):
    controller_module = types.ModuleType("app.clients.controller")
    controller_module.ControllerClient = ActiveController
    controller_module.ControllerClientError = RuntimeError
    sys.modules["app.clients.controller"] = controller_module
    module = load_service_module(
        "path_service",
        stubs={
            "app.repositories.flow_repository": {"FlowRepository": Flows},
            "app.repositories.platform_settings_repository": {
                "PlatformSettingsRepository": RuntimeSettings,
            },
            "app.services.dashboard_service": {"DashboardService": Dashboard},
        },
    )
    controller = ActiveController()
    service = module.PathService(
        Dashboard(),
        Flows(),
        controller,
        CongestedUtilization(),
        RuntimeSettings(70),
    )

    result = service.get_status()

    assert result["active_path"] == "backup"
    assert controller.recalculations == ["backup"]
    assert result["controller"]["path_control"]["status"] == "RECALCULATED"


def test_controller_balancing_suppresses_legacy_global_path_switch(
    load_service_module,
):
    controller_module = types.ModuleType("app.clients.controller")
    controller_module.ControllerClient = DistributedController
    controller_module.ControllerClientError = RuntimeError
    sys.modules["app.clients.controller"] = controller_module
    module = load_service_module(
        "path_service",
        stubs={
            "app.repositories.flow_repository": {"FlowRepository": Flows},
            "app.repositories.platform_settings_repository": {
                "PlatformSettingsRepository": RuntimeSettings,
            },
            "app.services.dashboard_service": {"DashboardService": Dashboard},
        },
    )
    controller = DistributedController()
    service = module.PathService(
        Dashboard(),
        Flows(),
        controller,
        CongestedUtilization(),
        RuntimeSettings(1),
    )

    result = service.get_status()

    assert result["path_distribution_mode"] == "balanced"
    assert result["path_capacity_pps"] == 1000
    assert result["path_distribution_threshold_pps"] == 800
    assert result["path_distribution_recovery_pps"] == 600
    assert result["paths"]["primary"]["active"] is True
    assert result["paths"]["backup"]["active"] is True
    assert controller.recalculations == []
