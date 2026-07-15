import unittest

from app.hosts import HostRegistry


class HostRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = HostRegistry()

    def test_learns_mac_ipv4_and_attachment_point(self):
        result = self.registry.learn(
            "00:00:00:00:00:01",
            dpid=1,
            port=1,
            ipv4="10.0.0.1",
        )

        self.assertEqual("learned", result.change)
        self.assertIsNone(result.previous)
        self.assertEqual(result.current, self.registry.get(result.current.mac))
        self.assertEqual(result.current, self.registry.get_by_ipv4("10.0.0.1"))

    def test_normalizes_uppercase_mac(self):
        result = self.registry.learn("AA:BB:CC:DD:EE:FF", 1, 2)

        self.assertEqual("aa:bb:cc:dd:ee:ff", result.current.mac)

    def test_updates_host_location_when_host_moves(self):
        self.registry.learn("00:00:00:00:00:01", 1, 1, "10.0.0.1")

        result = self.registry.learn("00:00:00:00:00:01", 4, 3)

        self.assertEqual("moved", result.change)
        self.assertEqual((1, 1), (result.previous.dpid, result.previous.port))
        self.assertEqual((4, 3), (result.current.dpid, result.current.port))
        self.assertEqual("10.0.0.1", result.current.ipv4)

    def test_updates_ipv4_without_losing_location(self):
        self.registry.learn("00:00:00:00:00:01", 1, 1)

        result = self.registry.learn(
            "00:00:00:00:00:01",
            1,
            1,
            "10.0.0.1",
        )

        self.assertEqual("ip_updated", result.change)
        self.assertEqual((1, 1), (result.current.dpid, result.current.port))

    def test_classifies_repeated_observation_as_refresh(self):
        self.registry.learn("00:00:00:00:00:01", 1, 1, "10.0.0.1")

        result = self.registry.learn(
            "00:00:00:00:00:01",
            1,
            1,
            "10.0.0.1",
        )

        self.assertEqual("refreshed", result.change)

    def test_snapshot_is_sorted_by_mac(self):
        self.registry.learn("00:00:00:00:00:03", 1, 3)
        self.registry.learn("00:00:00:00:00:01", 1, 1)

        self.assertEqual(
            ["00:00:00:00:00:01", "00:00:00:00:00:03"],
            [host.mac for host in self.registry.snapshot()],
        )

    def test_rejects_invalid_identity_or_attachment(self):
        invalid_observations = (
            ("invalid", 1, 1, None),
            ("00:00:00:00:00:01", -1, 1, None),
            ("00:00:00:00:00:01", 1, 0, None),
            ("00:00:00:00:00:01", 1, 1, "999.0.0.1"),
        )

        for observation in invalid_observations:
            with self.subTest(observation=observation):
                with self.assertRaises(ValueError):
                    self.registry.learn(*observation)


if __name__ == "__main__":
    unittest.main()

