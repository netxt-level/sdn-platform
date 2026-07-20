"""Thread-safe lifecycle tracking for backend-requested Flow Rules."""

from dataclasses import dataclass
from threading import Event
from threading import RLock


@dataclass(frozen=True)
class FlowOperationStatus:
    rule_id: str
    switch_id: str
    dpid: int
    cookie: int
    state: str
    flow_xid: int
    request_xids: tuple[int, ...]
    barrier_xid: int
    operation: str = "install"
    meter_id: int | None = None
    error: str | None = None


@dataclass
class _TrackedFlowOperation:
    datapath: object
    status: FlowOperationStatus
    completed: Event


class FlowOperationRegistry:
    """Confirm external Flow-Mods without marking them applied prematurely."""

    def __init__(self):
        self._records = {}
        self._lock = RLock()

    def submit(
        self,
        datapath,
        rule_id,
        switch_id,
        cookie,
        sender,
        meter_id=None,
    ):
        """Submit idempotently; the lock closes the send/register reply race."""
        with self._lock:
            existing = self._records.get(rule_id)
            if existing is not None and existing.status.state in {
                "pending",
                "installed",
            }:
                return existing.status
            if existing is not None and existing.status.state == "removing":
                raise ValueError("Flow Rule removal is already in progress")

            request_messages, barrier_request = sender()
            request_messages = tuple(request_messages)
            if not request_messages:
                raise ValueError(
                    "Flow Rule submission requires at least one request"
                )
            flow_mod = request_messages[-1]
            status = FlowOperationStatus(
                rule_id=rule_id,
                switch_id=switch_id,
                dpid=datapath.id,
                cookie=cookie,
                state="pending",
                flow_xid=flow_mod.xid,
                request_xids=tuple(
                    message.xid for message in request_messages
                ),
                barrier_xid=barrier_request.xid,
                operation="install",
                meter_id=meter_id,
            )
            self._records[rule_id] = _TrackedFlowOperation(
                datapath=datapath,
                status=status,
                completed=Event(),
            )
            return status

    def submit_removal(
        self,
        datapath,
        rule_id,
        switch_id,
        cookie,
        sender,
    ):
        """Submit an idempotent strict-delete operation for one rule."""
        with self._lock:
            existing = self._records.get(rule_id)
            if existing is not None:
                if existing.status.state == "removed":
                    return existing.status
                if existing.status.state == "removing":
                    return existing.status
                if existing.status.state == "pending":
                    raise ValueError(
                        "Flow Rule installation is still in progress"
                    )
                meter_id = existing.status.meter_id
            else:
                meter_id = None

            request_messages, barrier_request = sender()
            request_messages = tuple(request_messages)
            if not request_messages:
                raise ValueError(
                    "Flow Rule removal requires at least one request"
                )
            flow_mod = request_messages[-1]
            status = FlowOperationStatus(
                rule_id=rule_id,
                switch_id=switch_id,
                dpid=datapath.id,
                cookie=cookie,
                state="removing",
                flow_xid=flow_mod.xid,
                request_xids=tuple(
                    message.xid for message in request_messages
                ),
                barrier_xid=barrier_request.xid,
                operation="remove",
                meter_id=meter_id,
            )
            self._records[rule_id] = _TrackedFlowOperation(
                datapath=datapath,
                status=status,
                completed=Event(),
            )
            return status

    def wait(self, rule_id, timeout_seconds):
        with self._lock:
            record = self._records[rule_id]
            completed = record.completed

        completed.wait(timeout_seconds)
        with self._lock:
            record = self._records[rule_id]
            if record.status.state in {"pending", "removing"}:
                removing = record.status.state == "removing"
                record.status = self._replace(
                    record.status,
                    state="delete_failed" if removing else "failed",
                    error=(
                        "Barrier Reply timed out after "
                        f"{timeout_seconds:g} seconds"
                    ),
                )
                record.completed.set()
            return record.status

    def mark_confirmed(self, datapath, barrier_xid):
        with self._lock:
            for record in self._records.values():
                status = record.status
                if (
                    record.datapath is datapath
                    and status.state in {"pending", "removing"}
                    and status.barrier_xid == barrier_xid
                ):
                    record.status = self._replace(
                        status,
                        state=(
                            "installed"
                            if status.state == "pending"
                            else "removed"
                        ),
                    )
                    record.completed.set()
                    return record.status
        return None

    def mark_installed(self, datapath, barrier_xid):
        """Backward-compatible install confirmation helper."""
        status = self.mark_confirmed(datapath, barrier_xid)
        if status is None or status.state != "installed":
            return None
        return status.rule_id

    def mark_failed(self, datapath, request_xid, error):
        with self._lock:
            for record in self._records.values():
                status = record.status
                if (
                    record.datapath is datapath
                    and status.state in {"pending", "removing"}
                    and request_xid in (
                        *status.request_xids,
                        status.barrier_xid,
                    )
                ):
                    record.status = self._replace(
                        status,
                        state=(
                            "delete_failed"
                            if status.state == "removing"
                            else "failed"
                        ),
                        error=str(error),
                    )
                    record.completed.set()
                    return status.rule_id
        return None

    def fail_pending_for_datapath(self, datapath, error):
        failed = []
        with self._lock:
            for record in self._records.values():
                if (
                    record.datapath is datapath
                    and record.status.state in {"pending", "removing"}
                ):
                    removing = record.status.state == "removing"
                    record.status = self._replace(
                        record.status,
                        state="delete_failed" if removing else "failed",
                        error=str(error),
                    )
                    record.completed.set()
                    failed.append(record.status.rule_id)
        return tuple(failed)

    def mark_removed(self, datapath, cookie, reason):
        with self._lock:
            for record in self._records.values():
                status = record.status
                if (
                    record.datapath is datapath
                    and status.cookie == cookie
                    and status.state in {"installed", "removing"}
                ):
                    record.status = self._replace(
                        status,
                        state=reason,
                    )
                    record.completed.set()
                    return record.status
        return None

    def get(self, rule_id):
        with self._lock:
            record = self._records.get(rule_id)
            return None if record is None else record.status

    def snapshot(self):
        with self._lock:
            return tuple(
                self._records[rule_id].status
                for rule_id in sorted(self._records)
            )

    @staticmethod
    def _replace(status, *, state, error=None):
        return FlowOperationStatus(
            rule_id=status.rule_id,
            switch_id=status.switch_id,
            dpid=status.dpid,
            cookie=status.cookie,
            state=state,
            flow_xid=status.flow_xid,
            request_xids=status.request_xids,
            barrier_xid=status.barrier_xid,
            operation=status.operation,
            meter_id=status.meter_id,
            error=error,
        )
