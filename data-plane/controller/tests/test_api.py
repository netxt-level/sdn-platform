import unittest
from types import SimpleNamespace

from app.api import build_health_response
from app.api import build_switches_response
from app.api import build_topology_response
from app.api import create_api
from app.api import FlowRuleInstallRequest
from app.config import ControllerSettings
from app.datapaths import DatapathRegistry
from app.flow_operations import FlowOperationRegistry
from app.hosts import HostRegistry
from app.meters import MeterRegistry
from app.table_miss import TableMissRegistry
from app.stats import StatsRegistry
from app.topology import ActiveTopology
from app.topology import WEIGHTED_SWITCH_GRAPH


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
            request_xids=(11,),
            barrier_xid=12,
            operation="install",
            meter_id=None,
            error=None,
        )


class RemovedFlowOperations:
    def __init__(self):
        self.removals = []
        self.status = SimpleNamespace(
            rule_id="rule-1",
            switch_id="s1",
            dpid=1,
            cookie=0x5344E20000000001,
            state="installed",
            flow_xid=11,
            request_xids=(11,),
            barrier_xid=12,
            operation="install",
            meter_id=None,
            error=None,
        )

    def snapshot(self):
        return (self.status,)

    def get(self, rule_id):
        return self.status if rule_id == self.status.rule_id else None

    def submit_removal(self, **removal):
        self.removals.append(removal)

    def wait(self, rule_id, timeout_seconds):
        return SimpleNamespace(
            **{
                **vars(self.status),
                "state": "removed",
                "operation": "remove",
            }
        )


class ControllerApiTests(unittest.TestCase):
    def setUp(self):
        self.datapaths = DatapathRegistry()
        self.table_miss_statuses = TableMissRegistry()
        self.flow_operations = FlowOperationRegistry()
        self.meters = MeterRegistry()
        self.hosts = HostRegistry()
        self.topology = ActiveTopology(WEIGHTED_SWITCH_GRAPH)
        self.stats = StatsRegistry()
        self.recalculation_reasons = []
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
            self.meters,
            self.hosts,
            self.topology,
            self._recalculate,
            self.stats,
            self.settings,
        )

        routes = {
            route.path
            for route in app.routes
            if getattr(route, "methods", None)
        }

        self.assertEqual(
            {
                "/health",
                "/switches",
                "/flow-rules",
                "/flow-rules/{rule_id}",
                "/meters",
                "/topology",
                "/stats",
                "/paths/recalculate",
            },
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
            self.meters,
            self.hosts,
            self.topology,
            self._recalculate,
            self.stats,
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

    def test_missing_switch_is_resolved_from_learned_source_host(self):
        self.datapaths.register(FakeDatapath(1))
        self.hosts.learn(
            mac="00:00:00:00:00:03",
            ipv4="10.0.0.3",
            dpid=1,
            port=3,
        )
        operations = AppliedFlowOperations()
        app = create_api(
            self.datapaths,
            self.table_miss_statuses,
            operations,
            self.meters,
            self.hosts,
            self.topology,
            self._recalculate,
            self.stats,
            self.settings,
        )
        endpoint = next(
            route.endpoint
            for route in app.routes
            if route.path == "/flow-rules" and "POST" in route.methods
        )

        response = endpoint(FlowRuleInstallRequest(
            rule_id="auto-rule",
            match={"ipv4_src": "10.0.0.3"},
            action="DROP",
            priority=500,
        ))

        self.assertEqual("s1", response["switch_id"])
        self.assertEqual(
            "s1",
            operations.submissions[0]["switch_id"],
        )

    def test_topology_response_contains_switch_links_and_learned_hosts(self):
        self.topology.connect_switch(1)
        self.topology.connect_switch(2)
        self.topology.set_link_port_state(1, 2, True)
        self.topology.set_link_port_state(2, 1, True)
        self.hosts.learn(
            mac="00:00:00:00:00:01",
            ipv4="10.0.0.1",
            dpid=1,
            port=1,
        )

        response = build_topology_response(self.topology, self.hosts)

        self.assertEqual("connected", response["switches"][0]["state"])
        primary_link = next(
            link
            for link in response["links"]
            if (link["source"], link["destination"]) == ("s1", "s2")
        )
        self.assertEqual("active", primary_link["state"])
        self.assertEqual("h1", response["hosts"][0]["name"])
        self.assertEqual("s1", response["hosts"][0]["switch_id"])

    def test_path_recalculation_endpoint_invalidates_l2_flows(self):
        app = create_api(
            self.datapaths,
            self.table_miss_statuses,
            self.flow_operations,
            self.meters,
            self.hosts,
            self.topology,
            self._recalculate,
            self.stats,
            self.settings,
        )
        endpoint = next(
            route.endpoint
            for route in app.routes
            if route.path == "/paths/recalculate"
        )

        response = endpoint()

        self.assertEqual("RECALCULATED", response["status"])
        self.assertEqual(4, response["invalidated_switches"])
        self.assertEqual(
            ["controller_api_request"],
            self.recalculation_reasons,
        )

    def test_delete_flow_rule_returns_only_after_removed_confirmation(self):
        self.datapaths.register(FakeDatapath(1))
        operations = RemovedFlowOperations()
        app = create_api(
            self.datapaths,
            self.table_miss_statuses,
            operations,
            self.meters,
            self.hosts,
            self.topology,
            self._recalculate,
            self.stats,
            self.settings,
        )
        endpoint = next(
            route.endpoint
            for route in app.routes
            if route.path == "/flow-rules/{rule_id}"
        )

        response = endpoint("rule-1")

        self.assertEqual("REMOVED", response["status"])
        self.assertEqual("remove", response["operation"])
        self.assertEqual(1, len(operations.removals))
        self.assertEqual("rule-1", operations.removals[0]["rule_id"])

    def _recalculate(self, reason):
        self.recalculation_reasons.append(reason)
        return 4


if __name__ == "__main__":
    unittest.main()
