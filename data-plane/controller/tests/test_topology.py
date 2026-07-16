import unittest

from app.topology import ActiveTopology
from app.topology import get_flood_output_ports
from app.topology import is_host_facing_port
from app.topology import PRIMARY_SWITCH_GRAPH
from app.topology import SWITCH_LINK_PORTS
from app.topology import WEIGHTED_SWITCH_GRAPH


class TopologyPortRoleTests(unittest.TestCase):
    def test_accepts_configured_host_facing_ports(self):
        self.assertTrue(is_host_facing_port(1, 1))
        self.assertTrue(is_host_facing_port(1, 2))
        self.assertTrue(is_host_facing_port(1, 3))
        self.assertTrue(is_host_facing_port(4, 3))

    def test_rejects_transit_ports(self):
        self.assertFalse(is_host_facing_port(1, 4))
        self.assertFalse(is_host_facing_port(1, 5))
        self.assertFalse(is_host_facing_port(4, 1))
        self.assertFalse(is_host_facing_port(4, 2))

    def test_rejects_ports_on_unknown_switches(self):
        self.assertFalse(is_host_facing_port(99, 1))

    def test_flood_tree_excludes_ingress_and_backup_link(self):
        self.assertEqual((2, 3, 4, 5), get_flood_output_ports(1, 1))
        self.assertEqual((1,), get_flood_output_ports(2, 2))
        self.assertEqual((), get_flood_output_ports(3, 1))
        self.assertEqual((1,), get_flood_output_ports(4, 3))

    def test_backup_link_cannot_enter_flood_tree(self):
        self.assertEqual((), get_flood_output_ports(3, 2))
        self.assertEqual((), get_flood_output_ports(4, 2))

    def test_unknown_switch_has_no_flood_ports(self):
        self.assertEqual((), get_flood_output_ports(99, 1))

    def test_switch_link_ports_are_symmetric(self):
        for source, neighbors in SWITCH_LINK_PORTS.items():
            for destination in neighbors:
                with self.subTest(source=source, destination=destination):
                    self.assertIn(source, SWITCH_LINK_PORTS[destination])

    def test_primary_graph_excludes_s3_s4_backup_link(self):
        self.assertNotIn(4, PRIMARY_SWITCH_GRAPH[3])
        self.assertNotIn(3, PRIMARY_SWITCH_GRAPH[4])

    def test_weighted_graph_contains_symmetric_positive_link_costs(self):
        for source, neighbors in WEIGHTED_SWITCH_GRAPH.items():
            for destination, cost in neighbors.items():
                with self.subTest(source=source, destination=destination):
                    self.assertGreater(cost, 0)
                    self.assertEqual(
                        cost,
                        WEIGHTED_SWITCH_GRAPH[destination][source],
                    )

    def test_weighted_graph_prefers_upper_primary_links(self):
        self.assertLess(
            WEIGHTED_SWITCH_GRAPH[1][2] + WEIGHTED_SWITCH_GRAPH[2][4],
            WEIGHTED_SWITCH_GRAPH[1][3] + WEIGHTED_SWITCH_GRAPH[3][4],
        )


class ActiveTopologyTests(unittest.TestCase):
    def setUp(self):
        self.topology = ActiveTopology(WEIGHTED_SWITCH_GRAPH)

    def test_snapshot_contains_only_connected_switches_and_links(self):
        self.topology.connect_switch(1)
        self.topology.connect_switch(2)

        self.assertEqual(
            {1: {2: 1}, 2: {1: 1}},
            self.topology.snapshot(),
        )

    def test_disconnect_removes_switch_and_attached_links(self):
        for dpid in WEIGHTED_SWITCH_GRAPH:
            self.topology.connect_switch(dpid)

        self.topology.disconnect_switch(2)

        self.assertEqual(
            {
                1: {3: 10},
                3: {1: 10, 4: 10},
                4: {3: 10},
            },
            self.topology.snapshot(),
        )

    def test_link_state_removes_and_restores_both_directions(self):
        for dpid in WEIGHTED_SWITCH_GRAPH:
            self.topology.connect_switch(dpid)

        self.assertTrue(self.topology.set_link_state(1, 2, False))
        graph = self.topology.snapshot()
        self.assertNotIn(2, graph[1])
        self.assertNotIn(1, graph[2])

        self.assertTrue(self.topology.set_link_state(1, 2, True))
        graph = self.topology.snapshot()
        self.assertEqual(1, graph[1][2])
        self.assertEqual(1, graph[2][1])

    def test_repeated_state_update_reports_no_change(self):
        self.assertTrue(self.topology.connect_switch(1))
        self.assertFalse(self.topology.connect_switch(1))
        self.assertTrue(self.topology.disconnect_switch(1))
        self.assertFalse(self.topology.disconnect_switch(1))
        self.assertFalse(self.topology.set_link_state(1, 2, True))

    def test_snapshot_is_a_defensive_copy(self):
        self.topology.connect_switch(1)
        self.topology.connect_switch(2)
        snapshot = self.topology.snapshot()

        snapshot[1].clear()

        self.assertEqual({2: 1}, self.topology.snapshot()[1])

    def test_rejects_unknown_switch_link_and_invalid_state(self):
        with self.assertRaisesRegex(ValueError, "unknown configured switch"):
            self.topology.connect_switch(99)
        with self.assertRaisesRegex(ValueError, "unknown configured link"):
            self.topology.set_link_state(1, 4, False)
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            self.topology.set_link_state(1, 2, 1)

    def test_rejects_asymmetric_configured_graph(self):
        with self.assertRaisesRegex(ValueError, "must be symmetric"):
            ActiveTopology({1: {2: 1}, 2: {1: 2}})


if __name__ == "__main__":
    unittest.main()
