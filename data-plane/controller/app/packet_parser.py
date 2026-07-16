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


@dataclass(frozen=True)
class PacketMetadata:
    source_mac: str
    destination_mac: str
    ethertype: int
    source_ipv4: str | None


def _is_unicast_source(mac):
    try:
        first_octet = int(mac.split(":", maxsplit=1)[0], 16)
    except (AttributeError, ValueError):
        return False
    return mac != "00:00:00:00:00:00" and not first_octet & 1


def parse_packet_metadata(data):
    """Return learnable source and forwarding metadata for an Ethernet frame."""
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

    return PacketMetadata(
        source_mac=source_mac,
        destination_mac=ethernet_header.dst.lower(),
        ethertype=ethernet_header.ethertype,
        source_ipv4=source_ipv4,
    )


def parse_source_identity(data):
    """Return a learnable Ethernet source and optional IPv4 address."""
    metadata = parse_packet_metadata(data)
    if metadata is None:
        return None
    return SourceIdentity(
        mac=metadata.source_mac,
        ipv4=metadata.source_ipv4,
    )


def classify_destination(mac):
    """Classify a destination MAC for structured forwarding logs."""
    try:
        normalized = mac.lower()
        first_octet = int(normalized.split(":", maxsplit=1)[0], 16)
    except (AttributeError, TypeError, ValueError):
        return "invalid"
    if normalized == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    return "multicast" if first_octet & 1 else "unknown_unicast"
