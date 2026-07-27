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

    def __init__(self, capacity_bps: int, capacity_pps: int = 1000):
        if capacity_bps <= 0:
            raise ValueError("capacity_bps must be positive")
        if capacity_pps <= 0:
            raise ValueError("capacity_pps must be positive")
        self.capacity_bps = capacity_bps
        self.capacity_pps = capacity_pps
        self._previous_at: datetime | None = None
        self._previous_counters: dict[
            tuple[str, int],
            tuple[int, int, int, int],
        ] = {}
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
        topology_ports = self._topology_ports(topology)
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
                max_rx_pps = 0.0
                max_tx_pps = 0.0
                total_port_pps = 0.0
                max_port_pps = 0.0
                port_usage = []
                allowed_ports = topology_ports.get(switch_id)
                for key, (
                    rx_bytes,
                    tx_bytes,
                    rx_packets,
                    tx_packets,
                ) in current.items():
                    if key[0] != switch_id:
                        continue
                    if allowed_ports and key[1] not in allowed_ports:
                        continue
                    previous = self._previous_counters.get(key)
                    if previous is None:
                        port_usage.append(
                            self._port_usage_item(key[1], sampled=False)
                        )
                        continue
                    rx_bps = max(0, rx_bytes - previous[0]) * 8 / interval
                    tx_bps = max(0, tx_bytes - previous[1]) * 8 / interval
                    rx_pps = max(0, rx_packets - previous[2]) / interval
                    tx_pps = max(0, tx_packets - previous[3]) / interval
                    port_pps = rx_pps + tx_pps
                    max_rx_bps = max(max_rx_bps, rx_bps)
                    max_tx_bps = max(max_tx_bps, tx_bps)
                    max_rx_pps = max(max_rx_pps, rx_pps)
                    max_tx_pps = max(max_tx_pps, tx_pps)
                    total_port_pps += port_pps
                    max_port_pps = max(max_port_pps, port_pps)
                    port_usage.append(
                        self._port_usage_item(
                            key[1],
                            rx_bps=rx_bps,
                            tx_bps=tx_bps,
                            rx_pps=rx_pps,
                            tx_pps=tx_pps,
                            sampled=True,
                        )
                    )

                bps = max(max_rx_bps, max_tx_bps)
                utilization = min(
                    100.0,
                    (bps / self.capacity_bps) * 100,
                )
                pps = max(max_port_pps, total_port_pps / 2)
                pps_utilization = (pps / self.capacity_pps) * 100
                switch_sampled = any(
                    bool(item["sampled"]) for item in port_usage
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
                    "pps": round(pps, 2),
                    "rx_pps": round(max_rx_pps, 2),
                    "tx_pps": round(max_tx_pps, 2),
                    "pps_utilization": round(pps_utilization, 2),
                    "capacity_pps": self.capacity_pps,
                    "sample_interval_seconds": round(interval, 3),
                    "sampled": switch_sampled,
                    "ports": sorted(
                        port_usage,
                        key=lambda item: item["port_no"],
                    ),
                    "status": self._status(
                        states.get(switch_id, "unknown"),
                        utilization,
                        sampled=switch_sampled,
                    ),
                    "pps_status": self._status(
                        states.get(switch_id, "unknown"),
                        pps_utilization,
                        sampled=switch_sampled,
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
                current_ports=sorted(
                    port_no
                    for current_switch_id, port_no in current
                    if current_switch_id == switch_id
                    and (
                        not topology_ports.get(switch_id)
                        or port_no in topology_ports[switch_id]
                    )
                ),
            )
            for switch_id in switch_ids
        ]

    @staticmethod
    def _port_counters(
        stats: dict[str, Any],
    ) -> dict[tuple[str, int], tuple[int, int, int, int]]:
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
                    int(port.get("rx_packets") or 0),
                    int(port.get("tx_packets") or 0),
                )
        return counters

    @staticmethod
    def _topology_ports(
        topology: dict[str, Any],
    ) -> dict[str, set[int]]:
        ports: dict[str, set[int]] = {}

        def add(switch_id: Any, port_no: Any) -> None:
            if not switch_id or not port_no:
                return
            ports.setdefault(str(switch_id), set()).add(int(port_no))

        for link in topology.get("links", []):
            add(link.get("source"), link.get("source_port"))
            add(link.get("destination"), link.get("destination_port"))
        for host in topology.get("hosts", []):
            add(host.get("switch_id"), host.get("port"))
        return ports

    def _port_usage_item(
        self,
        port_no: int,
        *,
        rx_bps: float = 0.0,
        tx_bps: float = 0.0,
        rx_pps: float = 0.0,
        tx_pps: float = 0.0,
        sampled: bool,
    ) -> dict[str, Any]:
        bps = max(rx_bps, tx_bps)
        pps = rx_pps + tx_pps
        return {
            "port_no": port_no,
            "bps": round(bps, 2),
            "rx_bps": round(rx_bps, 2),
            "tx_bps": round(tx_bps, 2),
            "utilization": round(
                min(100.0, (bps / self.capacity_bps) * 100),
                2,
            ),
            "capacity_bps": self.capacity_bps,
            "pps": round(pps, 2),
            "rx_pps": round(rx_pps, 2),
            "tx_pps": round(tx_pps, 2),
            "pps_utilization": round(
                (pps / self.capacity_pps) * 100,
                2,
            ),
            "capacity_pps": self.capacity_pps,
            "sampled": sampled,
        }

    def _usage_item(
        self,
        switch_id: str,
        *,
        state: str,
        dpid: str | None,
        current_ports: list[int],
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
                "pps": 0.0,
                "rx_pps": 0.0,
                "tx_pps": 0.0,
                "pps_utilization": 0.0,
                "capacity_pps": self.capacity_pps,
                "sample_interval_seconds": None,
                "sampled": False,
                "ports": [
                    self._port_usage_item(port_no, sampled=False)
                    for port_no in current_ports
                ],
                "status": self._status(state, 0.0, sampled=False),
                "pps_status": self._status(state, 0.0, sampled=False),
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
                "pps": 0.0,
                "rx_pps": 0.0,
                "tx_pps": 0.0,
                "pps_utilization": 0.0,
                "ports": [
                    {
                        **port,
                        "bps": 0.0,
                        "rx_bps": 0.0,
                        "tx_bps": 0.0,
                        "utilization": 0.0,
                        "pps": 0.0,
                        "rx_pps": 0.0,
                        "tx_pps": 0.0,
                        "pps_utilization": 0.0,
                    }
                    for port in previous.get("ports", [])
                ],
                "status": "disconnected",
                "pps_status": "disconnected",
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
            "pps_status": self._status(
                state,
                float(previous["pps_utilization"]),
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
