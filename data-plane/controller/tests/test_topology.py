import unittest

from app.topology import get_flood_output_ports
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


if __name__ == "__main__":
    unittest.main()
