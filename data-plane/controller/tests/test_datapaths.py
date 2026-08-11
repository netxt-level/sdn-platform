import unittest

from app.datapaths import DatapathRegistry


class FakeDatapath:
    def __init__(self, dpid):
        self.id = dpid


class DatapathRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = DatapathRegistry()

    def test_registers_and_returns_datapath_by_dpid(self):
        datapath = FakeDatapath(1)

        previous = self.registry.register(datapath)

        self.assertIsNone(previous)
        self.assertIs(datapath, self.registry.get(1))
        self.assertEqual(1, len(self.registry))

    def test_reconnection_replaces_previous_datapath(self):
        previous_datapath = FakeDatapath(1)
        current_datapath = FakeDatapath(1)
        self.registry.register(previous_datapath)

        replaced = self.registry.register(current_datapath)

        self.assertIs(previous_datapath, replaced)
        self.assertIs(current_datapath, self.registry.get(1))
        self.assertEqual(1, len(self.registry))

    def test_stale_disconnect_does_not_remove_current_datapath(self):
        stale_datapath = FakeDatapath(1)
        current_datapath = FakeDatapath(1)
        self.registry.register(stale_datapath)
        self.registry.register(current_datapath)

        removed = self.registry.unregister(stale_datapath)

        self.assertFalse(removed)
        self.assertIs(current_datapath, self.registry.get(1))

    def test_disconnect_removes_current_datapath(self):
        datapath = FakeDatapath(1)
        self.registry.register(datapath)

        removed = self.registry.unregister(datapath)

        self.assertTrue(removed)
        self.assertIsNone(self.registry.get(1))
        self.assertEqual(0, len(self.registry))

    def test_snapshot_is_sorted_by_dpid(self):
        datapath_4 = FakeDatapath(4)
        datapath_1 = FakeDatapath(1)
        datapath_2 = FakeDatapath(2)
        self.registry.register(datapath_4)
        self.registry.register(datapath_1)
        self.registry.register(datapath_2)

        snapshot = self.registry.snapshot()

        self.assertEqual([1, 2, 4], [datapath.id for datapath in snapshot])

    def test_rejects_datapath_without_negotiated_dpid(self):
        with self.assertRaisesRegex(ValueError, "DPID has not been negotiated"):
            self.registry.register(FakeDatapath(None))


if __name__ == "__main__":
    unittest.main()
