"""Parse source host identity from OpenFlow Packet-In payloads."""

from dataclasses import dataclass
import struct

from os_ken.lib.packet import arp
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import packet


@dataclass(frozen=True)
class SourceIdentity:
    mac: str
    ipv4: str | None


def _is_unicast_source(mac):
    try:
        first_octet = int(mac.split(":", maxsplit=1)[0], 16)
    except (AttributeError, ValueError):
        return False
    return mac != "00:00:00:00:00:00" and not first_octet & 1


def parse_source_identity(data):
    """Return a learnable Ethernet source and optional IPv4 address."""
    if not data:
        return None

    try:
        parsed = packet.Packet(data)
    except (AssertionError, TypeError, ValueError, struct.error):
        return None

    ethernet_header = parsed.get_protocol(ethernet.ethernet)
    if ethernet_header is None:
        return None

    source_mac = ethernet_header.src.lower()
    if (
        ethernet_header.ethertype == ether_types.ETH_TYPE_LLDP
        or not _is_unicast_source(source_mac)
    ):
        return None

    source_ipv4 = None
    arp_payload = parsed.get_protocol(arp.arp)
    if arp_payload is not None:
        if arp_payload.src_mac.lower() == source_mac:
            source_ipv4 = arp_payload.src_ip
    else:
        ipv4_header = parsed.get_protocol(ipv4.ipv4)
        if ipv4_header is not None:
            source_ipv4 = ipv4_header.src

    return SourceIdentity(mac=source_mac, ipv4=source_ipv4)

