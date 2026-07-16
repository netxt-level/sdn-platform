import unittest

from app.routing import PathHop
from app.routing import RoutingError
from app.routing import calculate_bidirectional_routes
from app.routing import calculate_output_hops
from app.routing import calculate_unweighted_path
from app.topology import PRIMARY_SWITCH_GRAPH
from app.topology import SWITCH_LINK_PORTS


class PathCalculationTests(unittest.TestCase):
    def test_calculates_primary_path_deterministically(self):
        path = calculate_unweighted_path(PRIMARY_SWITCH_GRAPH, 1, 4)

        self.assertEqual((1, 2, 4), path)

    def test_calculates_reverse_path(self):
        path = calculate_unweighted_path(PRIMARY_SWITCH_GRAPH, 4, 1)

        self.assertEqual((4, 2, 1), path)

    def test_same_switch_path_contains_one_switch(self):
        self.assertEqual(
            (1,),
            calculate_unweighted_path(PRIMARY_SWITCH_GRAPH, 1, 1),
        )

    def test_equal_length_paths_choose_lowest_next_dpid(self):
        graph = {
            1: (3, 2),
            2: (1, 4),
            3: (1, 4),
            4: (2, 3),
        }

        self.assertEqual((1, 2, 4), calculate_unweighted_path(graph, 1, 4))

    def test_primary_path_does_not_use_backup_link(self):
        path = calculate_unweighted_path(PRIMARY_SWITCH_GRAPH, 3, 4)

        self.assertEqual((3, 1, 2, 4), path)

    def test_rejects_unknown_or_unreachable_switch(self):
        with self.assertRaisesRegex(RoutingError, "unknown source switch"):
            calculate_unweighted_path(PRIMARY_SWITCH_GRAPH, 99, 1)
        with self.assertRaisesRegex(RoutingError, "unknown destination switch"):
            calculate_unweighted_path(PRIMARY_SWITCH_GRAPH, 1, 99)
        with self.assertRaisesRegex(RoutingError, "no path"):
            calculate_unweighted_path({1: (), 2: ()}, 1, 2)


class OutputPortCalculationTests(unittest.TestCase):
    def test_calculates_forward_and_reverse_output_ports(self):
        routes = calculate_bidirectional_routes(
            graph=PRIMARY_SWITCH_GRAPH,
            link_ports=SWITCH_LINK_PORTS,
            source_dpid=1,
            source_port=1,
            destination_dpid=4,
            destination_port=3,
        )

        self.assertEqual((1, 2, 4), routes.forward.switches)
        self.assertEqual(
            (
                PathHop(dpid=1, output_port=4),
                PathHop(dpid=2, output_port=2),
                PathHop(dpid=4, output_port=3),
            ),
            routes.forward.hops,
        )
        self.assertEqual((4, 2, 1), routes.reverse.switches)
        self.assertEqual(
            (
                PathHop(dpid=4, output_port=1),
                PathHop(dpid=2, output_port=1),
                PathHop(dpid=1, output_port=1),
            ),
            routes.reverse.hops,
        )

    def test_same_switch_route_outputs_to_host_port(self):
        routes = calculate_bidirectional_routes(
            graph=PRIMARY_SWITCH_GRAPH,
            link_ports=SWITCH_LINK_PORTS,
            source_dpid=1,
            source_port=1,
            destination_dpid=1,
            destination_port=3,
        )

        self.assertEqual((PathHop(1, 3),), routes.forward.hops)
        self.assertEqual((PathHop(1, 1),), routes.reverse.hops)

    def test_rejects_missing_link_port_or_invalid_destination_port(self):
        with self.assertRaisesRegex(RoutingError, "missing output port"):
            calculate_output_hops((1, 2), {1: {}}, 3)
        with self.assertRaisesRegex(RoutingError, "invalid destination port"):
            calculate_output_hops((1,), SWITCH_LINK_PORTS, 0)


if __name__ == "__main__":
    unittest.main()
