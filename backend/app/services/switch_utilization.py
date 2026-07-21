from __future__ import annotations

from datetime import datetime
from threading import RLock
from typing import Any


LOCAL_PORT_MIN = 0xFFFFFF00
MIN_SAMPLE_INTERVAL_SECONDS = 1.0
WARNING_UTILIZATION_PERCENT = 70.0
CRITICAL_UTILIZATION_PERCENT = 90.0


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class SwitchUtilizationTracker:
    """Convert cumulative OpenFlow port counters into switch utilization."""

    def __init__(self, capacity_bps: int):
        if capacity_bps <= 0:
            raise ValueError("capacity_bps must be positive")
        self.capacity_bps = capacity_bps
        self._previous_at: datetime | None = None
        self._previous_counters: dict[tuple[str, int], tuple[int, int]] = {}
        self._last_usage: dict[str, dict[str, Any]] = {}
        self._lock = RLock()

    def update(
        self,
        stats: dict[str, Any],
        topology: dict[str, Any],
    ) -> list[dict[str, Any]]:
        with self._lock:
            return self._update_locked(stats, topology)

    def _update_locked(
        self,
        stats: dict[str, Any],
        topology: dict[str, Any],
    ) -> list[dict[str, Any]]:
        sampled_at = _parse_timestamp(stats.get("updated_at"))
        current = self._port_counters(stats)
        interval = (
            None
            if sampled_at is None or self._previous_at is None
            else (sampled_at - self._previous_at).total_seconds()
        )
        can_sample = (
            interval is not None
            and interval >= MIN_SAMPLE_INTERVAL_SECONDS
        )

        states = {
            item.get("switch_id"): item.get("state", "unknown")
            for item in topology.get("switches", [])
            if item.get("switch_id")
        }
        dpids = {
            item.get("switch_id"): item.get("dpid")
            for item in topology.get("switches", [])
            if item.get("switch_id")
        }
        switch_ids = sorted(
            states.keys() | {switch_id for switch_id, _ in current}
        )

        if can_sample:
            for switch_id in switch_ids:
                max_rx_bps = 0.0
                max_tx_bps = 0.0
                for key, (rx_bytes, tx_bytes) in current.items():
                    if key[0] != switch_id:
                        continue
                    previous = self._previous_counters.get(key)
                    if previous is None:
                        continue
                    max_rx_bps = max(
                        max_rx_bps,
                        max(0, rx_bytes - previous[0]) * 8 / interval,
                    )
                    max_tx_bps = max(
                        max_tx_bps,
                        max(0, tx_bytes - previous[1]) * 8 / interval,
                    )

                bps = max(max_rx_bps, max_tx_bps)
                utilization = min(
                    100.0,
                    (bps / self.capacity_bps) * 100,
                )
                self._last_usage[switch_id] = {
                    "switch_id": switch_id,
                    "dpid": dpids.get(switch_id),
                    "state": states.get(switch_id, "unknown"),
                    "bps": round(bps, 2),
                    "rx_bps": round(max_rx_bps, 2),
                    "tx_bps": round(max_tx_bps, 2),
                    "utilization": round(utilization, 2),
                    "capacity_bps": self.capacity_bps,
                    "sample_interval_seconds": round(interval, 3),
                    "sampled": True,
                    "status": self._status(
                        states.get(switch_id, "unknown"),
                        utilization,
                        sampled=True,
                    ),
                }

        if sampled_at is not None and (
            self._previous_at is None
            or sampled_at > self._previous_at
            and (
                interval is None
                or interval >= MIN_SAMPLE_INTERVAL_SECONDS
            )
        ):
            self._previous_at = sampled_at
            self._previous_counters = current

        return [
            self._usage_item(
                switch_id,
                state=states.get(switch_id, "unknown"),
                dpid=dpids.get(switch_id),
            )
            for switch_id in switch_ids
        ]

    @staticmethod
    def _port_counters(
        stats: dict[str, Any],
    ) -> dict[tuple[str, int], tuple[int, int]]:
        counters = {}
        for switch in stats.get("switches", []):
            switch_id = switch.get("switch_id")
            if not switch_id:
                continue
            for port in switch.get("ports", []):
                port_no = int(port.get("port_no") or 0)
                if port_no <= 0 or port_no >= LOCAL_PORT_MIN:
                    continue
                counters[(switch_id, port_no)] = (
                    int(port.get("rx_bytes") or 0),
                    int(port.get("tx_bytes") or 0),
                )
        return counters

    def _usage_item(
        self,
        switch_id: str,
        *,
        state: str,
        dpid: str | None,
    ) -> dict[str, Any]:
        previous = self._last_usage.get(switch_id)
        if previous is None:
            return {
                "switch_id": switch_id,
                "dpid": dpid,
                "state": state,
                "bps": 0.0,
                "rx_bps": 0.0,
                "tx_bps": 0.0,
                "utilization": 0.0,
                "capacity_bps": self.capacity_bps,
                "sample_interval_seconds": None,
                "sampled": False,
                "status": self._status(state, 0.0, sampled=False),
            }
        if state != "connected":
            return {
                **previous,
                "dpid": dpid or previous.get("dpid"),
                "state": state,
                "bps": 0.0,
                "rx_bps": 0.0,
                "tx_bps": 0.0,
                "utilization": 0.0,
                "status": "disconnected",
            }
        return {
            **previous,
            "dpid": dpid or previous.get("dpid"),
            "state": state,
            "status": self._status(
                state,
                float(previous["utilization"]),
                sampled=bool(previous["sampled"]),
            ),
        }

    @staticmethod
    def _status(state: str, utilization: float, *, sampled: bool) -> str:
        if state != "connected":
            return "disconnected"
        if not sampled:
            return "sampling"
        if utilization >= CRITICAL_UTILIZATION_PERCENT:
            return "critical"
        if utilization >= WARNING_UTILIZATION_PERCENT:
            return "warning"
        return "normal"
