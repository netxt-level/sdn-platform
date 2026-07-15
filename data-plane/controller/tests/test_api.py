import unittest

from app.api import build_health_response
from app.api import build_switches_response
from app.api import create_api
from app.config import ControllerSettings
from app.datapaths import DatapathRegistry


class FakeDatapath:
    def __init__(self, dpid):
        self.id = dpid


class ControllerApiTests(unittest.TestCase):
    def setUp(self):
        self.datapaths = DatapathRegistry()
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
        self.datapaths.register(FakeDatapath(4))
        self.datapaths.register(FakeDatapath(1))

        response = build_switches_response(self.datapaths)

        self.assertEqual(
            {
                "switches": [
                    {
                        "dpid": "0000000000000001",
                        "state": "connected",
                        "table_miss_installed": True,
                    },
                    {
                        "dpid": "0000000000000004",
                        "state": "connected",
                        "table_miss_installed": True,
                    },
                ]
            },
            response,
        )

    def test_only_health_and_switch_routes_are_exposed(self):
        app = create_api(self.datapaths, self.settings)

        routes = {
            route.path
            for route in app.routes
            if getattr(route, "methods", None)
        }

        self.assertEqual({"/health", "/switches"}, routes)


if __name__ == "__main__":
    unittest.main()
