import unittest
from types import SimpleNamespace

from app.api import build_health_response
from app.api import build_switches_response
from app.api import create_api
from app.api import FlowRuleInstallRequest
from app.config import ControllerSettings
from app.datapaths import DatapathRegistry
from app.flow_operations import FlowOperationRegistry
from app.table_miss import TableMissRegistry


class FakeDatapath:
    def __init__(self, dpid):
        self.id = dpid


class AppliedFlowOperations:
    def __init__(self):
        self.submissions = []

    def snapshot(self):
        return ()

    def submit(self, **submission):
        self.submissions.append(submission)

    def wait(self, rule_id, timeout_seconds):
        return SimpleNamespace(
            rule_id=rule_id,
            switch_id="s1",
            dpid=1,
            cookie=0x5344E20000000001,
            state="installed",
            flow_xid=11,
            barrier_xid=12,
            error=None,
        )


class ControllerApiTests(unittest.TestCase):
    def setUp(self):
        self.datapaths = DatapathRegistry()
        self.table_miss_statuses = TableMissRegistry()
        self.flow_operations = FlowOperationRegistry()
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

    def test_health_switch_and_flow_rule_routes_are_exposed(self):
        app = create_api(
            self.datapaths,
            self.table_miss_statuses,
            self.flow_operations,
            self.settings,
        )

        routes = {
            route.path
            for route in app.routes
            if getattr(route, "methods", None)
        }

        self.assertEqual(
            {"/health", "/switches", "/flow-rules"},
            routes,
        )

    def test_post_flow_rule_returns_only_after_applied_confirmation(self):
        datapath = FakeDatapath(1)
        self.datapaths.register(datapath)
        operations = AppliedFlowOperations()
        app = create_api(
            self.datapaths,
            self.table_miss_statuses,
            operations,
            self.settings,
        )

        endpoint = next(
            route.endpoint
            for route in app.routes
            if route.path == "/flow-rules" and "POST" in route.methods
        )
        response = endpoint(FlowRuleInstallRequest(
            rule_id="rule-1",
            switch_id="s1",
            match={"ipv4_src": "10.0.0.2"},
            action="DROP",
            priority=500,
        ))

        self.assertEqual("APPLIED", response["status"])
        self.assertEqual("rule-1", response["controller_rule_id"])
        self.assertEqual(1, len(operations.submissions))


if __name__ == "__main__":
    unittest.main()
