import unittest
from types import SimpleNamespace

from os_ken.lib.packet import ether_types

from app.packet_parser import PacketMetadata
from app.path_distribution import BACKUP_PATH
from app.path_distribution import BALANCED_MODE
from app.path_distribution import PRIMARY_PATH
from app.path_distribution import PathDistributionPolicy
from app.path_distribution import prefer_path
from app.routing import calculate_dijkstra_path
from app.topology import WEIGHTED_SWITCH_GRAPH


def port(port_no, rx_packets=0, tx_packets=0):
    return SimpleNamespace(
        port_no=port_no,
        rx_packets=rx_packets,
        tx_packets=tx_packets,
    )


def tcp_metadata(source_port, *, reverse=False):
    source = ("10.0.0.1", source_port, "00:00:00:00:00:01")
    destination = ("10.0.0.100", 80, "00:00:00:00:01:00")
    if reverse:
        source, destination = destination, source
    return PacketMetadata(
        source_mac=source[2],
        destination_mac=destination[2],
        ethertype=ether_types.ETH_TYPE_IP,
        source_ipv4=source[0],
        destination_ipv4=destination[0],
        ip_proto=6,
        source_port=source[1],
        destination_port=destination[1],
    )


class PathDistributionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.policy = PathDistributionPolicy(
            threshold_pps=800,
            recovery_pps=600,
            clock=lambda: self.now,
        )

    def sample(self, packet_count):
        return self.policy.update_s1_port_stats(
            [port(4, rx_packets=packet_count)],
        )

    def test_enables_balancing_at_eighty_percent_capacity(self):
        self.sample(0)
        self.now = 1.0

        update = self.sample(800)

        self.assertTrue(update.changed)
        self.assertEqual(BALANCED_MODE, update.mode)
        self.assertEqual(800.0, update.pps)

    def test_returns_after_three_samples_below_sixty_percent_capacity(self):
        self.sample(0)
        self.now = 1.0
        self.sample(800)
        self.now = 2.0
        update = self.sample(1450)
        self.assertFalse(update.changed)
        self.assertEqual(BALANCED_MODE, update.mode)
        self.assertEqual(650.0, update.pps)

        self.now = 3.0
        update = self.sample(2049)
        self.assertFalse(update.changed)
        self.assertEqual(BALANCED_MODE, update.mode)
        self.assertEqual(599.0, update.pps)

        self.now = 4.0
        update = self.sample(2648)
        self.assertFalse(update.changed)
        self.assertEqual(BALANCED_MODE, update.mode)

        self.now = 5.0
        update = self.sample(3247)

        self.assertTrue(update.changed)
        self.assertEqual(PRIMARY_PATH, update.mode)

    def test_balanced_tcp_hash_is_symmetric_and_uses_both_paths(self):
        self.sample(0)
        self.now = 1.0
        self.sample(800)

        selections = {}
        for source_port in range(40000, 40100):
            forward = tcp_metadata(source_port)
            reverse = tcp_metadata(source_port, reverse=True)
            selections[source_port] = self.policy.select_path(forward)
            self.assertEqual(
                selections[source_port],
                self.policy.select_path(reverse),
            )

        self.assertEqual(
            {PRIMARY_PATH, BACKUP_PATH},
            set(selections.values()),
        )

    def test_non_tcp_traffic_stays_on_primary(self):
        self.sample(0)
        self.now = 1.0
        self.sample(800)
        metadata = PacketMetadata(
            source_mac="00:00:00:00:00:03",
            destination_mac="00:00:00:00:01:00",
            ethertype=ether_types.ETH_TYPE_IP,
            source_ipv4="10.0.0.3",
            destination_ipv4="10.0.0.100",
            ip_proto=1,
            source_port=None,
            destination_port=None,
        )

        self.assertEqual(PRIMARY_PATH, self.policy.select_path(metadata))

    def test_preferred_graph_uses_requested_live_path(self):
        primary = calculate_dijkstra_path(
            prefer_path(WEIGHTED_SWITCH_GRAPH, PRIMARY_PATH),
            1,
            4,
        )
        backup = calculate_dijkstra_path(
            prefer_path(WEIGHTED_SWITCH_GRAPH, BACKUP_PATH),
            1,
            4,
        )

        self.assertEqual((1, 2, 4), primary.switches)
        self.assertEqual((1, 3, 4), backup.switches)


if __name__ == "__main__":
    unittest.main()
