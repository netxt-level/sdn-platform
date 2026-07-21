"""Thread-safe snapshots of bounded OpenFlow port and flow counters."""

from datetime import datetime
from datetime import timezone
from threading import RLock


class StatsRegistry:
    def __init__(self):
        self._ports = {}
        self._flows = {}
        self._updated_at = None
        self._lock = RLock()

    def update_ports(self, dpid, entries):
        with self._lock:
            self._ports[dpid] = tuple(
                {
                    "port_no": item.port_no,
                    "rx_packets": item.rx_packets,
                    "tx_packets": item.tx_packets,
                    "rx_bytes": item.rx_bytes,
                    "tx_bytes": item.tx_bytes,
                    "rx_errors": item.rx_errors,
                    "tx_errors": item.tx_errors,
                }
                for item in entries
            )
            self._updated_at = datetime.now(timezone.utc).isoformat()

    def update_flows(self, dpid, entries):
        with self._lock:
            self._flows[dpid] = tuple(
                {
                    "table_id": item.table_id,
                    "priority": item.priority,
                    "cookie": f"0x{item.cookie:016x}",
                    "packet_count": item.packet_count,
                    "byte_count": item.byte_count,
                    "duration_sec": item.duration_sec,
                }
                for item in entries
            )
            self._updated_at = datetime.now(timezone.utc).isoformat()

    def snapshot(self):
        with self._lock:
            dpids = sorted(set(self._ports) | set(self._flows))
            return {
                "updated_at": self._updated_at,
                "switches": [
                    {
                        "switch_id": f"s{dpid}",
                        "dpid": f"{dpid:016x}",
                        "ports": list(self._ports.get(dpid, ())),
                        "flows": list(self._flows.get(dpid, ())),
                    }
                    for dpid in dpids
                ],
            }
