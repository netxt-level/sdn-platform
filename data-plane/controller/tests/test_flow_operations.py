import unittest
from types import SimpleNamespace

from app.flow_operations import FlowOperationRegistry


class FlowOperationRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = FlowOperationRegistry()
        self.datapath = SimpleNamespace(id=1)
        self.send_count = 0

    def sender(self):
        self.send_count += 1
        return (SimpleNamespace(xid=11),), SimpleNamespace(xid=12)

    def submit(self, rule_id="rule-1"):
        return self.registry.submit(
            self.datapath,
            rule_id,
            "s1",
            0x1234,
            self.sender,
        )

    def test_confirms_matching_barrier_and_keeps_submission_idempotent(self):
        pending = self.submit()

        self.assertEqual("pending", pending.state)
        self.assertEqual("rule-1", self.registry.mark_installed(
            self.datapath,
            12,
        ))
        installed = self.registry.wait("rule-1", 0.01)
        repeated = self.submit()

        self.assertEqual("installed", installed.state)
        self.assertEqual("installed", repeated.state)
        self.assertEqual(1, self.send_count)

    def test_matching_openflow_error_marks_operation_failed(self):
        self.submit()

        rule_id = self.registry.mark_failed(
            self.datapath,
            11,
            "OpenFlow rejected the rule",
        )
        failed = self.registry.wait("rule-1", 0.01)

        self.assertEqual("rule-1", rule_id)
        self.assertEqual("failed", failed.state)
        self.assertEqual("OpenFlow rejected the rule", failed.error)

    def test_meter_request_error_is_tracked_and_expiration_is_recorded(self):
        def meter_sender():
            return (
                SimpleNamespace(xid=10),
                SimpleNamespace(xid=11),
            ), SimpleNamespace(xid=12)

        self.registry.submit(
            self.datapath,
            "meter-rule",
            "s1",
            0x1235,
            meter_sender,
            meter_id=7,
        )
        self.assertEqual(
            "meter-rule",
            self.registry.mark_failed(
                self.datapath,
                10,
                "meter rejected",
            ),
        )

        self.registry.submit(
            self.datapath,
            "meter-rule",
            "s1",
            0x1235,
            meter_sender,
            meter_id=7,
        )
        self.registry.mark_installed(self.datapath, 12)
        expired = self.registry.mark_removed(
            self.datapath,
            0x1235,
            "expired",
        )

        self.assertEqual("expired", expired.state)
        self.assertEqual(7, expired.meter_id)

    def test_wait_timeout_fails_operation(self):
        self.submit()

        failed = self.registry.wait("rule-1", 0.001)

        self.assertEqual("failed", failed.state)
        self.assertIn("Barrier Reply timed out", failed.error)

    def test_disconnect_unblocks_all_pending_operations(self):
        self.submit("rule-1")
        self.submit("rule-2")

        failed = self.registry.fail_pending_for_datapath(
            self.datapath,
            "switch disconnected",
        )

        self.assertEqual(("rule-1", "rule-2"), failed)
        self.assertEqual(
            "failed",
            self.registry.wait("rule-1", 0.01).state,
        )

    def test_removal_is_confirmed_by_barrier_and_is_idempotent(self):
        self.submit()
        self.registry.mark_installed(self.datapath, 12)

        removing = self.registry.submit_removal(
            self.datapath,
            "rule-1",
            "s1",
            0x1234,
            self.sender,
        )
        confirmed = self.registry.mark_confirmed(
            self.datapath,
            12,
        )
        removed = self.registry.wait("rule-1", 0.01)
        repeated = self.registry.submit_removal(
            self.datapath,
            "rule-1",
            "s1",
            0x1234,
            self.sender,
        )

        self.assertEqual("removing", removing.state)
        self.assertEqual("removed", confirmed.state)
        self.assertEqual("removed", removed.state)
        self.assertEqual("removed", repeated.state)
        self.assertEqual(2, self.send_count)

    def test_flow_removed_event_completes_pending_removal(self):
        self.submit()
        self.registry.mark_installed(self.datapath, 12)
        self.registry.submit_removal(
            self.datapath,
            "rule-1",
            "s1",
            0x1234,
            self.sender,
        )

        removed = self.registry.mark_removed(
            self.datapath,
            0x1234,
            "removed",
        )

        self.assertEqual("removed", removed.state)
        self.assertEqual(
            "removed",
            self.registry.wait("rule-1", 0.01).state,
        )

    def test_removal_timeout_is_explicit_and_retryable(self):
        self.submit()
        self.registry.mark_installed(self.datapath, 12)
        self.registry.submit_removal(
            self.datapath,
            "rule-1",
            "s1",
            0x1234,
            self.sender,
        )

        failed = self.registry.wait("rule-1", 0.001)

        self.assertEqual("delete_failed", failed.state)
        retried = self.registry.submit_removal(
            self.datapath,
            "rule-1",
            "s1",
            0x1234,
            self.sender,
        )
        self.assertEqual("removing", retried.state)


if __name__ == "__main__":
    unittest.main()
