import unittest

from app.meters import MeterRegistry


class MeterRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = MeterRegistry()

    def test_allocates_stable_meter_for_repeated_rule(self):
        first = self.registry.allocate(1, "rule-1", 100)
        repeated = self.registry.allocate(1, "rule-1", 100)

        self.assertTrue(first.created)
        self.assertFalse(repeated.created)
        self.assertEqual(first.meter_id, repeated.meter_id)

    def test_reuses_compatible_meter_and_releases_after_last_rule(self):
        first = self.registry.allocate(1, "rule-1", 100)
        second = self.registry.allocate(1, "rule-2", 100)

        self.assertEqual(first.meter_id, second.meter_id)
        self.assertIsNone(self.registry.release(1, "rule-1"))
        self.assertEqual(
            first.meter_id,
            self.registry.release(1, "rule-2"),
        )
        self.assertEqual((), self.registry.snapshot())

    def test_different_rate_or_switch_gets_a_different_meter(self):
        first = self.registry.allocate(1, "rule-1", 100)
        different_rate = self.registry.allocate(1, "rule-2", 200)
        different_switch = self.registry.allocate(2, "rule-3", 100)

        self.assertNotEqual(first.meter_id, different_rate.meter_id)
        self.assertNotEqual(first.dpid, different_switch.dpid)

    def test_disconnect_releases_all_switch_meter_state(self):
        first = self.registry.allocate(1, "rule-1", 100)
        second = self.registry.allocate(1, "rule-2", 200)
        self.registry.allocate(2, "rule-3", 100)

        released = self.registry.release_datapath(1)

        self.assertEqual(
            tuple(sorted((first.meter_id, second.meter_id))),
            released,
        )
        self.assertEqual(1, len(self.registry.snapshot()))


if __name__ == "__main__":
    unittest.main()
