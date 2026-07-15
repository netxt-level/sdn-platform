"""Thread-safe host location learning independent from OpenFlow objects."""

from dataclasses import dataclass
from ipaddress import IPv4Address
import re
from threading import RLock


MAC_PATTERN = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


@dataclass(frozen=True)
class HostLocation:
    """Latest known attachment point and IPv4 address for a host MAC."""

    mac: str
    dpid: int
    port: int
    ipv4: str | None = None


@dataclass(frozen=True)
class HostLearningResult:
    """Describe how a host observation changed the registry."""

    change: str
    current: HostLocation
    previous: HostLocation | None


class HostRegistry:
    """Learn and query the latest host location by source MAC address."""

    def __init__(self):
        self._hosts = {}
        self._lock = RLock()

    @staticmethod
    def _normalize_mac(mac):
        normalized = str(mac).lower()
        if not MAC_PATTERN.fullmatch(normalized):
            raise ValueError(f"invalid MAC address: {mac}")
        return normalized

    @staticmethod
    def _validate_location(dpid, port):
        if not isinstance(dpid, int) or dpid < 0:
            raise ValueError(f"invalid DPID: {dpid}")
        if not isinstance(port, int) or port <= 0:
            raise ValueError(f"invalid input port: {port}")

    @staticmethod
    def _normalize_ipv4(ipv4):
        if ipv4 is None:
            return None
        return str(IPv4Address(ipv4))

    def learn(self, mac, dpid, port, ipv4=None):
        """Record a source observation and return its change classification."""
        normalized_mac = self._normalize_mac(mac)
        self._validate_location(dpid, port)
        normalized_ipv4 = self._normalize_ipv4(ipv4)

        with self._lock:
            previous = self._hosts.get(normalized_mac)
            effective_ipv4 = normalized_ipv4
            if effective_ipv4 is None and previous is not None:
                effective_ipv4 = previous.ipv4

            current = HostLocation(
                mac=normalized_mac,
                dpid=dpid,
                port=port,
                ipv4=effective_ipv4,
            )
            self._hosts[normalized_mac] = current

            if previous is None:
                change = "learned"
            elif (previous.dpid, previous.port) != (dpid, port):
                change = "moved"
            elif previous.ipv4 != effective_ipv4:
                change = "ip_updated"
            else:
                change = "refreshed"

            return HostLearningResult(
                change=change,
                current=current,
                previous=previous,
            )

    def get(self, mac):
        normalized_mac = self._normalize_mac(mac)
        with self._lock:
            return self._hosts.get(normalized_mac)

    def get_by_ipv4(self, ipv4):
        normalized_ipv4 = self._normalize_ipv4(ipv4)
        with self._lock:
            return next(
                (
                    host
                    for host in self._hosts.values()
                    if host.ipv4 == normalized_ipv4
                ),
                None,
            )

    def snapshot(self):
        with self._lock:
            return tuple(self._hosts[mac] for mac in sorted(self._hosts))

    def __len__(self):
        with self._lock:
            return len(self._hosts)

