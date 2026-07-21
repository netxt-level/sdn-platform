import sys
import types


class Dashboard:
    def get_summary(self):
        return {"current_bps": 0, "network_status": "normal"}


class Flows:
    def list_flows(self):
        return []


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
                {"source": "s1", "destination": "s3", "state": "active"},
                {"source": "s3", "destination": "s4", "state": "active"},
            ],
        }

    def get_stats(self):
        return {"switches": [{"switch_id": "s1"}]}


class Utilization:
    def update(self, stats, topology):
        return [
            {"switch_id": "s1", "utilization": 10.0},
            {"switch_id": "s2", "utilization": 40.0},
            {"switch_id": "s3", "utilization": 20.0},
            {"switch_id": "s4", "utilization": 30.0},
        ]


def test_path_status_uses_actual_controller_topology(load_service_module):
    controller_module = types.ModuleType("app.clients.controller")
    controller_module.ControllerClient = Controller
    controller_module.ControllerClientError = RuntimeError
    sys.modules["app.clients.controller"] = controller_module
    module = load_service_module(
        "path_service",
        stubs={
            "app.repositories.flow_repository": {"FlowRepository": Flows},
            "app.services.dashboard_service": {"DashboardService": Dashboard},
        },
    )
    service = module.PathService(Dashboard(), Flows(), Controller())

    result = service.get_status()

    assert result["active_path"] == "backup"
    assert result["controller"]["stats"]["switches"][0]["switch_id"] == "s1"


def test_path_status_uses_switch_counter_utilization(load_service_module):
    controller_module = types.ModuleType("app.clients.controller")
    controller_module.ControllerClient = Controller
    controller_module.ControllerClientError = RuntimeError
    sys.modules["app.clients.controller"] = controller_module
    module = load_service_module(
        "path_service",
        stubs={
            "app.repositories.flow_repository": {"FlowRepository": Flows},
            "app.services.dashboard_service": {"DashboardService": Dashboard},
        },
    )
    service = module.PathService(
        Dashboard(),
        Flows(),
        Controller(),
        Utilization(),
    )

    result = service.get_status()

    assert result["utilization_source"] == "openflow_port_counter_delta"
    assert result["switches"][1]["switch_id"] == "s2"
    assert result["paths"]["primary"]["utilization"] == 40.0
    assert result["paths"]["backup"]["utilization"] == 30.0
    assert result["links"][0]["utilization"] == 40.0
    assert result["links"][2]["utilization"] == 20.0
