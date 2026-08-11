"""PPS-triggered, per-flow path distribution for the fixed lab topology."""

from dataclasses import dataclass
import time
from threading import RLock
import zlib


PRIMARY_PATH = "primary"
BACKUP_PATH = "backup"
BALANCED_MODE = "balanced"
S1_DPID = 1
S1_TRANSIT_PORTS = frozenset({4, 5})
PRIMARY_PATH_COSTS = {
    (1, 2): 1,
    (2, 4): 1,
    (1, 3): 10,
    (3, 4): 10,
}
BACKUP_PATH_COSTS = {
    (1, 2): 10,
    (2, 4): 10,
    (1, 3): 1,
    (3, 4): 1,
}


@dataclass(frozen=True)
class DistributionUpdate:
    mode: str
    pps: float
    changed: bool


class PathDistributionPolicy:
    """Enable stable TCP-flow splitting after a sustained PPS threshold."""

    def __init__(
        self,
        threshold_pps=800.0,
        recovery_pps=600.0,
        recovery_samples=3,
        clock=None,
    ):
        threshold_pps = float(threshold_pps)
        recovery_pps = float(recovery_pps)
        if threshold_pps <= 0:
            raise ValueError("threshold_pps must be positive")
        if recovery_pps < 0 or recovery_pps >= threshold_pps:
            raise ValueError(
                "recovery_pps must be non-negative and below threshold_pps"
            )
        if not isinstance(recovery_samples, int) or recovery_samples <= 0:
            raise ValueError("recovery_samples must be a positive integer")
        self.threshold_pps = threshold_pps
        self.recovery_pps = recovery_pps
        self.recovery_samples = recovery_samples
        self._clock = clock or time.monotonic
        self._mode = PRIMARY_PATH
        self._pps = 0.0
        self._previous_packets = None
        self._previous_at = None
        self._below_recovery_samples = 0
        self._lock = RLock()

    @property
    def mode(self):
        with self._lock:
            return self._mode

    def update_s1_port_stats(self, entries):
        """Update aggregate s1 transit-link PPS and report mode transitions."""
        now = self._clock()
        packet_count = sum(
            max(0, int(item.rx_packets)) + max(0, int(item.tx_packets))
            for item in entries
            if int(item.port_no) in S1_TRANSIT_PORTS
        )

        with self._lock:
            changed = False
            if self._previous_packets is not None and self._previous_at is not None:
                interval = now - self._previous_at
                if interval > 0:
                    delta = packet_count - self._previous_packets
                    self._pps = max(0.0, delta / interval)
                    if (
                        self._mode == PRIMARY_PATH
                        and self._pps >= self.threshold_pps
                    ):
                        self._mode = BALANCED_MODE
                        self._below_recovery_samples = 0
                        changed = True
                    elif (
                        self._mode == BALANCED_MODE
                        and self._pps < self.recovery_pps
                    ):
                        self._below_recovery_samples += 1
                        if (
                            self._below_recovery_samples
                            >= self.recovery_samples
                        ):
                            self._mode = PRIMARY_PATH
                            self._below_recovery_samples = 0
                            changed = True
                    elif self._mode == BALANCED_MODE:
                        self._below_recovery_samples = 0

            self._previous_packets = packet_count
            self._previous_at = now
            return DistributionUpdate(
                mode=self._mode,
                pps=round(self._pps, 2),
                changed=changed,
            )

    def select_path(self, metadata):
        """Select one stable path for both directions of a TCP connection."""
        with self._lock:
            balanced = self._mode == BALANCED_MODE
        if not balanced or not metadata.is_tcp_flow:
            return PRIMARY_PATH

        endpoints = sorted(
            (
                (metadata.source_ipv4, metadata.source_port),
                (metadata.destination_ipv4, metadata.destination_port),
            )
        )
        identity = (
            f"{metadata.ip_proto}:"
            f"{endpoints[0][0]}:{endpoints[0][1]}-"
            f"{endpoints[1][0]}:{endpoints[1][1]}"
        ).encode("ascii")
        return BACKUP_PATH if zlib.crc32(identity) & 1 else PRIMARY_PATH

    def snapshot(self):
        with self._lock:
            return {
                "mode": self._mode,
                "pps": round(self._pps, 2),
                "threshold_pps": self.threshold_pps,
                "recovery_pps": self.recovery_pps,
                "recovery_samples": self.recovery_samples,
                "below_recovery_samples": self._below_recovery_samples,
                "strategy": "tcp_5tuple_hash",
            }


def prefer_path(graph, preferred_path):
    """Return a graph copy whose costs prefer the requested fixed path."""
    if preferred_path not in {PRIMARY_PATH, BACKUP_PATH}:
        raise ValueError(f"unsupported path: {preferred_path}")

    costs = (
        PRIMARY_PATH_COSTS
        if preferred_path == PRIMARY_PATH
        else BACKUP_PATH_COSTS
    )
    result = {source: dict(neighbors) for source, neighbors in graph.items()}
    for source, neighbors in result.items():
        for destination in neighbors:
            edge = tuple(sorted((source, destination)))
            if edge in costs:
                neighbors[destination] = costs[edge]
    return result
