import unittest

from app.table_miss import TableMissRegistry


class FakeDatapath:
    def __init__(self, dpid):
        self.id = dpid


class TableMissRegistryTests(unittest.TestCase):
    def setUp(self):
        self.now = 10.0
        self.registry = TableMissRegistry(
            timeout_seconds=5,
            clock=lambda: self.now,
        )
        self.datapath = FakeDatapath(1)

    def test_begins_pending_and_confirms_matching_barrier(self):
        status = self.registry.begin(self.datapath, 11, 12)

        self.assertEqual("pending", status.state)
        self.assertFalse(self.registry.mark_installed(self.datapath, 99))
        self.assertTrue(self.registry.mark_installed(self.datapath, 12))
        self.assertEqual("installed", self.registry.get(self.datapath).state)

    def test_matching_flow_error_marks_request_failed(self):
        self.registry.begin(self.datapath, 21, 22)

        self.assertTrue(
            self.registry.mark_failed(
                self.datapath,
                21,
                "OpenFlow error type=3 code=2",
            )
        )

        status = self.registry.get(self.datapath)
        self.assertEqual("failed", status.state)
        self.assertEqual("OpenFlow error type=3 code=2", status.error)
        self.assertFalse(self.registry.mark_installed(self.datapath, 22))

    def test_unrelated_error_does_not_change_pending_request(self):
        self.registry.begin(self.datapath, 31, 32)

        self.assertFalse(
            self.registry.mark_failed(self.datapath, 99, "unrelated")
        )
        self.assertEqual("pending", self.registry.get(self.datapath).state)

    def test_pending_request_expires_after_timeout(self):
        self.registry.begin(self.datapath, 41, 42)
        self.now = 15.0

        status = self.registry.get(self.datapath)

        self.assertEqual("failed", status.state)
        self.assertEqual(
            "Barrier Reply timed out after 5 seconds",
            status.error,
        )

    def test_stale_datapath_cannot_update_or_remove_current_request(self):
        current = FakeDatapath(1)
        self.registry.begin(self.datapath, 51, 52)
        self.registry.begin(current, 61, 62)

        self.assertFalse(self.registry.mark_installed(self.datapath, 52))
        self.assertFalse(
            self.registry.mark_failed(self.datapath, 51, "stale")
        )
        self.assertFalse(self.registry.remove(self.datapath))
        self.assertEqual("pending", self.registry.get(current).state)

    def test_removes_only_current_datapath_status(self):
        self.registry.begin(self.datapath, 71, 72)

        self.assertTrue(self.registry.remove(self.datapath))
        self.assertIsNone(self.registry.get(self.datapath))
        self.assertFalse(self.registry.remove(self.datapath))

    def test_rejects_invalid_timeout_identity_xid_and_error(self):
        for timeout in (0, -1, float("inf"), True):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(ValueError, "greater than zero"):
                    TableMissRegistry(timeout_seconds=timeout)

        with self.assertRaisesRegex(ValueError, "DPID"):
            self.registry.begin(FakeDatapath(None), 1, 2)
        for flow_xid in (-1, True):
            with self.subTest(flow_xid=flow_xid):
                with self.assertRaisesRegex(ValueError, "XID"):
                    self.registry.begin(self.datapath, flow_xid, 2)

        self.registry.begin(self.datapath, 81, 82)
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            self.registry.mark_failed(self.datapath, 81, " ")


if __name__ == "__main__":
    unittest.main()
