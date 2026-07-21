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
            "app.services.dashboard_service": {"DashboardService": Dashboard},
        },
    )
    service = module.PathService(Dashboard(), Flows(), Controller())

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
    assert result["links"][0]["utilization"] == 10.0
    assert result["links"][0]["bps"] == 1_000_000
    assert result["links"][2]["utilization"] == 20.0
