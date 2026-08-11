import unittest

from app.routing import PathHop
from app.routing import RoutingError
from app.routing import WeightedPath
from app.routing import calculate_bidirectional_routes
from app.routing import calculate_dijkstra_path
from app.routing import calculate_input_ports
from app.routing import calculate_output_hops
from app.routing import calculate_unweighted_path
from app.routing import calculate_weighted_bidirectional_routes
from app.topology import PRIMARY_SWITCH_GRAPH
from app.topology import SWITCH_LINK_PORTS
from app.topology import WEIGHTED_SWITCH_GRAPH


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


class InputPortCalculationTests(unittest.TestCase):
    def test_calculates_primary_path_input_ports(self):
        self.assertEqual(
            (1, 1, 1),
            calculate_input_ports((1, 2, 4), SWITCH_LINK_PORTS, 1),
        )

    def test_calculates_backup_and_reverse_input_ports(self):
        self.assertEqual(
            (1, 1, 2),
            calculate_input_ports((1, 3, 4), SWITCH_LINK_PORTS, 1),
        )
        self.assertEqual(
            (3, 2, 4),
            calculate_input_ports((4, 2, 1), SWITCH_LINK_PORTS, 3),
        )

    def test_same_switch_path_uses_source_host_port(self):
        self.assertEqual(
            (2,),
            calculate_input_ports((1,), SWITCH_LINK_PORTS, 2),
        )

    def test_rejects_missing_link_port_or_invalid_source_port(self):
        with self.assertRaisesRegex(RoutingError, "missing input port"):
            calculate_input_ports((1, 2), {2: {}}, 1)
        with self.assertRaisesRegex(RoutingError, "invalid source port"):
            calculate_input_ports((1,), SWITCH_LINK_PORTS, 0)


class DijkstraPathCalculationTests(unittest.TestCase):
    @staticmethod
    def copy_graph():
        return {
            switch: dict(neighbors)
            for switch, neighbors in WEIGHTED_SWITCH_GRAPH.items()
        }

    def test_selects_lowest_cost_primary_path(self):
        result = calculate_dijkstra_path(WEIGHTED_SWITCH_GRAPH, 1, 4)

        self.assertEqual(WeightedPath((1, 2, 4), 2), result)

    def test_uses_backup_path_when_primary_link_is_missing(self):
        graph = self.copy_graph()
        del graph[1][2]
        del graph[2][1]

        result = calculate_dijkstra_path(graph, 1, 4)

        self.assertEqual(WeightedPath((1, 3, 4), 20), result)
        self.assertEqual(
            (
                PathHop(dpid=1, output_port=5),
                PathHop(dpid=3, output_port=2),
                PathHop(dpid=4, output_port=3),
            ),
            calculate_output_hops(
                result.switches,
                SWITCH_LINK_PORTS,
                destination_port=3,
            ),
        )

    def test_link_cost_change_can_select_backup_path(self):
        graph = self.copy_graph()
        graph[1][3] = 0.5
        graph[3][1] = 0.5
        graph[3][4] = 0.5
        graph[4][3] = 0.5

        result = calculate_dijkstra_path(graph, 1, 4)

        self.assertEqual(WeightedPath((1, 3, 4), 1.0), result)

    def test_equal_cost_paths_choose_lexicographically_smallest_path(self):
        graph = self.copy_graph()
        graph[1][3] = 1
        graph[3][1] = 1
        graph[3][4] = 1
        graph[4][3] = 1

        result = calculate_dijkstra_path(graph, 1, 4)

        self.assertEqual(WeightedPath((1, 2, 4), 2), result)

    def test_same_switch_path_has_zero_cost(self):
        result = calculate_dijkstra_path(WEIGHTED_SWITCH_GRAPH, 1, 1)

        self.assertEqual(WeightedPath((1,), 0), result)

    def test_rejects_invalid_link_cost(self):
        for invalid_cost in (-1, float("inf"), float("nan"), "1", True):
            graph = self.copy_graph()
            graph[1][2] = invalid_cost

            with self.subTest(invalid_cost=invalid_cost):
                with self.assertRaisesRegex(RoutingError, "invalid link cost"):
                    calculate_dijkstra_path(graph, 1, 4)

    def test_rejects_unknown_or_unreachable_switch(self):
        with self.assertRaisesRegex(RoutingError, "unknown source switch"):
            calculate_dijkstra_path(WEIGHTED_SWITCH_GRAPH, 99, 1)
        with self.assertRaisesRegex(RoutingError, "unknown destination switch"):
            calculate_dijkstra_path(WEIGHTED_SWITCH_GRAPH, 1, 99)
        with self.assertRaisesRegex(RoutingError, "no path"):
            calculate_dijkstra_path({1: {}, 2: {}}, 1, 2)


class WeightedRouteCalculationTests(unittest.TestCase):
    def test_calculates_weighted_bidirectional_primary_routes(self):
        routes = calculate_weighted_bidirectional_routes(
            graph=WEIGHTED_SWITCH_GRAPH,
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

    def test_calculates_weighted_bidirectional_backup_routes(self):
        graph = {
            switch: dict(neighbors)
            for switch, neighbors in WEIGHTED_SWITCH_GRAPH.items()
        }
        del graph[1][2]
        del graph[2][1]

        routes = calculate_weighted_bidirectional_routes(
            graph=graph,
            link_ports=SWITCH_LINK_PORTS,
            source_dpid=1,
            source_port=1,
            destination_dpid=4,
            destination_port=3,
        )

        self.assertEqual((1, 3, 4), routes.forward.switches)
        self.assertEqual((4, 3, 1), routes.reverse.switches)
        self.assertEqual(5, routes.forward.hops[0].output_port)
        self.assertEqual(2, routes.reverse.hops[0].output_port)


if __name__ == "__main__":
    unittest.main()
