import tempfile
import unittest
from pathlib import Path

from analyzer.app.backend_client import DeliveryResult
from analyzer.app.outbox import DurableOutbox


class FakeBackendClient:
    def __init__(self, result: DeliveryResult):
        self.result = result
        self.calls = []

    def post(self, path, payload, label):
        self.calls.append((path, payload, label))
        return self.result


class DurableOutboxTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temp_dir.name) / "outbox.db")

    def tearDown(self):
        self.temp_dir.cleanup()

    def enqueue(self, outbox):
        return outbox.enqueue_batch(
            [
                {
                    "path": "/api/analyzer/packet-summary",
                    "label": "packet summary",
                    "payload": {"packet_count": 3},
                }
            ]
        )

    def test_messages_survive_outbox_recreation(self):
        outbox = DurableOutbox(self.database_path)
        self.assertEqual(self.enqueue(outbox), 1)

        reopened = DurableOutbox(self.database_path)

        self.assertEqual(reopened.pending_count(), 1)
        self.assertEqual(reopened.list_due(10)[0].payload, {"packet_count": 3})

    def test_successful_delivery_removes_message(self):
        outbox = DurableOutbox(self.database_path)
        self.enqueue(outbox)
        client = FakeBackendClient(DeliveryResult(success=True))

        result = outbox.deliver_due(client, 10, 1, 60)

        self.assertEqual(result.delivered, 1)
        self.assertEqual(outbox.pending_count(), 0)

    def test_retryable_failure_keeps_message(self):
        outbox = DurableOutbox(self.database_path)
        self.enqueue(outbox)
        client = FakeBackendClient(
            DeliveryResult(success=False, retryable=True, error="offline")
        )

        result = outbox.deliver_due(client, 10, 10, 60)

        self.assertEqual(result.retried, 1)
        self.assertEqual(outbox.pending_count(), 1)
        self.assertEqual(outbox.list_due(10, now=0), [])

    def test_non_retryable_failure_is_dead_lettered(self):
        outbox = DurableOutbox(self.database_path)
        self.enqueue(outbox)
        client = FakeBackendClient(
            DeliveryResult(success=False, retryable=False, error="HTTP 422")
        )

        result = outbox.deliver_due(client, 10, 1, 60)

        self.assertEqual(result.dead_lettered, 1)
        self.assertEqual(outbox.pending_count(), 0)
        self.assertEqual(outbox.dead_letter_count(), 1)


if __name__ == "__main__":
    unittest.main()
