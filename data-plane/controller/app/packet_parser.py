"""Parse source host identity from OpenFlow Packet-In payloads."""

from dataclasses import dataclass
import struct

from os_ken.lib.packet import arp
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import packet
from os_ken.lib.packet import tcp
from os_ken.lib.packet import udp


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
    destination_ipv4: str | None
    ip_proto: int | None
    source_port: int | None
    destination_port: int | None

    @property
    def is_tcp_flow(self):
        return (
            self.ethertype == ether_types.ETH_TYPE_IP
            and self.ip_proto == 6
            and self.source_ipv4 is not None
            and self.destination_ipv4 is not None
            and self.source_port is not None
            and self.destination_port is not None
        )


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
    destination_ipv4 = None
    ip_proto = None
    source_port = None
    destination_port = None
    arp_payload = parsed.get_protocol(arp.arp)
    if arp_payload is not None:
        if arp_payload.src_mac.lower() == source_mac:
            source_ipv4 = arp_payload.src_ip
            destination_ipv4 = arp_payload.dst_ip
    else:
        ipv4_header = parsed.get_protocol(ipv4.ipv4)
        if ipv4_header is not None:
            source_ipv4 = ipv4_header.src
            destination_ipv4 = ipv4_header.dst
            ip_proto = ipv4_header.proto
            tcp_header = parsed.get_protocol(tcp.tcp)
            udp_header = parsed.get_protocol(udp.udp)
            if tcp_header is not None:
                source_port = tcp_header.src_port
                destination_port = tcp_header.dst_port
            elif udp_header is not None:
                source_port = udp_header.src_port
                destination_port = udp_header.dst_port

    return PacketMetadata(
        source_mac=source_mac,
        destination_mac=ethernet_header.dst.lower(),
        ethertype=ethernet_header.ethertype,
        source_ipv4=source_ipv4,
        destination_ipv4=destination_ipv4,
        ip_proto=ip_proto,
        source_port=source_port,
        destination_port=destination_port,
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
