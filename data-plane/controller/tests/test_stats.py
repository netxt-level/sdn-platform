import unittest
from types import SimpleNamespace

from app.stats import StatsRegistry


class StatsRegistryTests(unittest.TestCase):
    def test_aggregates_port_and_flow_counters_by_switch(self):
        registry = StatsRegistry()
        registry.update_ports(1, [SimpleNamespace(
            port_no=1,
            rx_packets=10,
            tx_packets=20,
            rx_bytes=100,
            tx_bytes=200,
            rx_errors=0,
            tx_errors=1,
        )])
        registry.update_flows(1, [SimpleNamespace(
            table_id=0,
            priority=500,
            cookie=7,
            packet_count=30,
            byte_count=300,
            duration_sec=4,
        )])

        snapshot = registry.snapshot()

        self.assertIsNotNone(snapshot["updated_at"])
        self.assertEqual("s1", snapshot["switches"][0]["switch_id"])
        self.assertEqual(10, snapshot["switches"][0]["ports"][0]["rx_packets"])
        self.assertEqual(30, snapshot["switches"][0]["flows"][0]["packet_count"])


if __name__ == "__main__":
    unittest.main()
