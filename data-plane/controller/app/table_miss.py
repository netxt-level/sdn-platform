"""Thread-safe Table-Miss installation confirmation state."""

from dataclasses import dataclass
import math
from threading import RLock
import time


TABLE_MISS_CONFIRM_TIMEOUT = 5.0


@dataclass(frozen=True)
class TableMissStatus:
    state: str
    flow_xids: tuple[int, ...]
    barrier_xid: int
    error: str | None = None

    @property
    def flow_xid(self):
        """Backward-compatible primary Flow-Mod XID."""
        return self.flow_xids[0]


@dataclass
class _TrackedTableMiss:
    datapath: object
    status: TableMissStatus
    started_at: float


class TableMissRegistry:
    """Track one current Table-Miss request for each connected DPID."""

    def __init__(
        self,
        timeout_seconds=TABLE_MISS_CONFIRM_TIMEOUT,
        clock=None,
    ):
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("Table-Miss timeout must be greater than zero")
        self._timeout_seconds = float(timeout_seconds)
        self._clock = time.monotonic if clock is None else clock
        self._records = {}
        self._lock = RLock()

    @staticmethod
    def _dpid(datapath):
        dpid = getattr(datapath, "id", None)
        if not isinstance(dpid, int) or dpid < 0:
            raise ValueError("datapath DPID has not been negotiated")
        return dpid

    @staticmethod
    def _xid(value, name):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"invalid {name}: {value}")
        return value

    def begin(self, datapath, flow_xids, barrier_xid):
        """Start a pending confirmation for the latest Datapath generation."""
        dpid = self._dpid(datapath)
        if isinstance(flow_xids, int) and not isinstance(flow_xids, bool):
            flow_xids = (flow_xids,)
        else:
            try:
                flow_xids = tuple(flow_xids)
            except TypeError as error:
                raise ValueError("invalid Flow-Mod XIDs") from error
        if not flow_xids:
            raise ValueError("at least one Flow-Mod XID is required")
        status = TableMissStatus(
            state="pending",
            flow_xids=tuple(
                self._xid(flow_xid, "Flow-Mod XID")
                for flow_xid in flow_xids
            ),
            barrier_xid=self._xid(barrier_xid, "Barrier XID"),
        )
        with self._lock:
            self._records[dpid] = _TrackedTableMiss(
                datapath=datapath,
                status=status,
                started_at=self._clock(),
            )
        return status

    def mark_installed(self, datapath, barrier_xid):
        """Confirm a pending request when its Barrier Reply arrives."""
        dpid = self._dpid(datapath)
        barrier_xid = self._xid(barrier_xid, "Barrier XID")
        with self._lock:
            record = self._records.get(dpid)
            if (
                record is None
                or record.datapath is not datapath
                or record.status.state != "pending"
                or record.status.barrier_xid != barrier_xid
            ):
                return False
            record.status = TableMissStatus(
                state="installed",
                flow_xids=record.status.flow_xids,
                barrier_xid=record.status.barrier_xid,
            )
            return True

    def mark_failed(self, datapath, request_xid, error):
        """Fail a pending request when a matching OpenFlow Error arrives."""
        dpid = self._dpid(datapath)
        request_xid = self._xid(request_xid, "request XID")
        error = str(error).strip()
        if not error:
            raise ValueError("Table-Miss failure reason must not be empty")

        with self._lock:
            record = self._records.get(dpid)
            if (
                record is None
                or record.datapath is not datapath
                or record.status.state != "pending"
                or request_xid not in (
                    *record.status.flow_xids,
                    record.status.barrier_xid,
                )
            ):
                return False
            record.status = TableMissStatus(
                state="failed",
                flow_xids=record.status.flow_xids,
                barrier_xid=record.status.barrier_xid,
                error=error,
            )
            return True

    def remove(self, datapath):
        """Remove state only when the disconnect belongs to the current object."""
        dpid = self._dpid(datapath)
        with self._lock:
            record = self._records.get(dpid)
            if record is None or record.datapath is not datapath:
                return False
            del self._records[dpid]
            return True

    def get(self, datapath):
        """Return current status and convert overdue pending state to failed."""
        dpid = self._dpid(datapath)
        with self._lock:
            record = self._records.get(dpid)
            if record is None or record.datapath is not datapath:
                return None
            if (
                record.status.state == "pending"
                and self._clock() - record.started_at >= self._timeout_seconds
            ):
                record.status = TableMissStatus(
                    state="failed",
                    flow_xids=record.status.flow_xids,
                    barrier_xid=record.status.barrier_xid,
                    error=(
                        "Barrier Reply timed out after "
                        f"{self._timeout_seconds:g} seconds"
                    ),
                )
            return record.status
