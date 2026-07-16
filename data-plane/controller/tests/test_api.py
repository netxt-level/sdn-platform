import unittest

from app.api import build_health_response
from app.api import build_switches_response
from app.api import create_api
from app.config import ControllerSettings
from app.datapaths import DatapathRegistry
from app.table_miss import TableMissRegistry


class FakeDatapath:
    def __init__(self, dpid):
        self.id = dpid


class ControllerApiTests(unittest.TestCase):
    def setUp(self):
        self.datapaths = DatapathRegistry()
        self.table_miss_statuses = TableMissRegistry()
        self.settings = ControllerSettings(
            openflow_port=6653,
            rest_host="127.0.0.1",
            rest_port=8080,
        )

    def test_health_reports_ready_without_connected_switches(self):
        response = build_health_response(self.datapaths, self.settings)

        self.assertEqual(
            {
                "status": "ready",
                "openflow_version": "1.3",
                "openflow_port": 6653,
                "rest_port": 8080,
                "connected_switches": 0,
            },
            response,
        )

    def test_switches_are_sorted_and_do_not_expose_datapath_objects(self):
        dpid4 = FakeDatapath(4)
        dpid1 = FakeDatapath(1)
        self.datapaths.register(dpid4)
        self.datapaths.register(dpid1)
        self.table_miss_statuses.begin(dpid4, 41, 42)
        self.table_miss_statuses.begin(dpid1, 11, 12)
        self.table_miss_statuses.mark_installed(dpid1, 12)

        response = build_switches_response(
            self.datapaths,
            self.table_miss_statuses,
        )

        self.assertEqual(
            {
                "switches": [
                    {
                        "dpid": "0000000000000001",
                        "state": "connected",
                        "table_miss_state": "installed",
                        "table_miss_installed": True,
                        "table_miss_error": None,
                    },
                    {
                        "dpid": "0000000000000004",
                        "state": "connected",
                        "table_miss_state": "pending",
                        "table_miss_installed": False,
                        "table_miss_error": None,
                    },
                ]
            },
            response,
        )

    def test_only_health_and_switch_routes_are_exposed(self):
        app = create_api(
            self.datapaths,
            self.table_miss_statuses,
            self.settings,
        )

        routes = {
            route.path
            for route in app.routes
            if getattr(route, "methods", None)
        }

        self.assertEqual({"/health", "/switches"}, routes)


if __name__ == "__main__":
    unittest.main()
