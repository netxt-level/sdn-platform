import unittest

from app.topology import is_host_facing_port


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


if __name__ == "__main__":
    unittest.main()

