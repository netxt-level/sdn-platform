import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .backend_client import BackendClient


@dataclass(frozen=True)
class OutboxMessage:
    id: int
    path: str
    label: str
    payload: dict
    attempts: int


@dataclass(frozen=True)
class DeliveryBatchResult:
    delivered: int = 0
    retried: int = 0
    dead_lettered: int = 0


class DurableOutbox:
    def __init__(self, database_path: str):
        self.database_path = database_path
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS outbox_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL,
                    label TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    last_error TEXT,
                    created_at REAL NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS ix_outbox_delivery
                ON outbox_messages (status, next_attempt_at, id)
                """
            )

    def enqueue_batch(self, messages: Iterable[dict]) -> int:
        rows = [
            (
                message["path"],
                message["label"],
                json.dumps(message["payload"], separators=(",", ":")),
                time.time(),
            )
            for message in messages
        ]
        if not rows:
            return 0

        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO outbox_messages (path, label, payload, created_at)
                VALUES (?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def list_due(self, limit: int, now: float | None = None) -> list[OutboxMessage]:
        due_at = time.time() if now is None else now
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, path, label, payload, attempts
                FROM outbox_messages
                WHERE status = 'PENDING' AND next_attempt_at <= ?
                ORDER BY id
                LIMIT ?
                """,
                (due_at, limit),
            ).fetchall()
        return [
            OutboxMessage(
                id=row["id"],
                path=row["path"],
                label=row["label"],
                payload=json.loads(row["payload"]),
                attempts=row["attempts"],
            )
            for row in rows
        ]

    def acknowledge(self, message_id: int) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM outbox_messages WHERE id = ?",
                (message_id,),
            )

    def reschedule(
        self,
        message: OutboxMessage,
        error: str,
        retry_base_sec: float,
        retry_max_sec: float,
    ) -> None:
        attempts = message.attempts + 1
        exponent = min(attempts - 1, 30)
        delay = min(retry_max_sec, retry_base_sec * (2 ** exponent))
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE outbox_messages
                SET attempts = ?, next_attempt_at = ?, last_error = ?
                WHERE id = ?
                """,
                (attempts, time.time() + delay, error, message.id),
            )

    def dead_letter(self, message_id: int, error: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE outbox_messages
                SET status = 'DEAD', last_error = ?
                WHERE id = ?
                """,
                (error, message_id),
            )

    def pending_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM outbox_messages WHERE status = 'PENDING'"
            ).fetchone()
        return int(row["count"])

    def dead_letter_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM outbox_messages WHERE status = 'DEAD'"
            ).fetchone()
        return int(row["count"])

    def deliver_due(
        self,
        client: BackendClient,
        batch_size: int,
        retry_base_sec: float,
        retry_max_sec: float,
    ) -> DeliveryBatchResult:
        delivered = 0
        retried = 0
        dead_lettered = 0

        for message in self.list_due(batch_size):
            result = client.post(
                path=message.path,
                payload=message.payload,
                label=message.label,
            )
            if result.success:
                self.acknowledge(message.id)
                delivered += 1
            elif result.retryable:
                self.reschedule(
                    message,
                    result.error or "delivery failed",
                    retry_base_sec,
                    retry_max_sec,
                )
                retried += 1
            else:
                self.dead_letter(message.id, result.error or "delivery rejected")
                dead_lettered += 1

        return DeliveryBatchResult(
            delivered=delivered,
            retried=retried,
            dead_lettered=dead_lettered,
        )
