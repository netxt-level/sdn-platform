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
            "links": [
                {"source": "s1", "destination": "s3", "state": "active"},
                {"source": "s3", "destination": "s4", "state": "active"},
            ],
        }

    def get_stats(self):
        return {"switches": [{"switch_id": "s1"}]}


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
