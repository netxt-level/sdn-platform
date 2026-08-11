import unittest

from os_ken.lib.packet import arp
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import packet
from os_ken.lib.packet import tcp

from app.packet_parser import SourceIdentity
from app.packet_parser import classify_destination
from app.packet_parser import parse_packet_metadata
from app.packet_parser import parse_source_identity


def serialize_packet(*protocols):
    value = packet.Packet()
    for protocol in protocols:
        value.add_protocol(protocol)
    value.serialize()
    return bytes(value.data)


class PacketParserTests(unittest.TestCase):
    def test_extracts_forwarding_metadata(self):
        data = serialize_packet(
            ethernet.ethernet(
                dst="ff:ff:ff:ff:ff:ff",
                src="00:00:00:00:00:01",
                ethertype=ether_types.ETH_TYPE_ARP,
            ),
            arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac="00:00:00:00:00:01",
                src_ip="10.0.0.1",
                dst_mac="00:00:00:00:00:00",
                dst_ip="10.0.0.100",
            ),
        )

        metadata = parse_packet_metadata(data)

        self.assertEqual("00:00:00:00:00:01", metadata.source_mac)
        self.assertEqual("ff:ff:ff:ff:ff:ff", metadata.destination_mac)
        self.assertEqual(ether_types.ETH_TYPE_ARP, metadata.ethertype)
        self.assertEqual("10.0.0.1", metadata.source_ipv4)

    def test_extracts_source_from_arp_packet(self):
        source_mac = "00:00:00:00:00:01"
        data = serialize_packet(
            ethernet.ethernet(
                dst="ff:ff:ff:ff:ff:ff",
                src=source_mac,
                ethertype=ether_types.ETH_TYPE_ARP,
            ),
            arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac=source_mac,
                src_ip="10.0.0.1",
                dst_mac="00:00:00:00:00:00",
                dst_ip="10.0.0.100",
            ),
        )

        self.assertEqual(
            SourceIdentity(mac=source_mac, ipv4="10.0.0.1"),
            parse_source_identity(data),
        )

    def test_extracts_source_from_ipv4_packet(self):
        source_mac = "00:00:00:00:00:02"
        data = serialize_packet(
            ethernet.ethernet(
                dst="00:00:00:00:01:00",
                src=source_mac,
                ethertype=ether_types.ETH_TYPE_IP,
            ),
            ipv4.ipv4(src="10.0.0.2", dst="10.0.0.100"),
        )

        self.assertEqual(
            SourceIdentity(mac=source_mac, ipv4="10.0.0.2"),
            parse_source_identity(data),
        )

    def test_extracts_tcp_five_tuple_for_path_distribution(self):
        data = serialize_packet(
            ethernet.ethernet(
                dst="00:00:00:00:01:00",
                src="00:00:00:00:00:01",
                ethertype=ether_types.ETH_TYPE_IP,
            ),
            ipv4.ipv4(
                src="10.0.0.1",
                dst="10.0.0.100",
                proto=6,
            ),
            tcp.tcp(src_port=40123, dst_port=80),
        )

        metadata = parse_packet_metadata(data)

        self.assertTrue(metadata.is_tcp_flow)
        self.assertEqual("10.0.0.100", metadata.destination_ipv4)
        self.assertEqual(6, metadata.ip_proto)
        self.assertEqual(40123, metadata.source_port)
        self.assertEqual(80, metadata.destination_port)

    def test_keeps_ethernet_source_when_network_protocol_is_unknown(self):
        source_mac = "00:00:00:00:00:03"
        data = serialize_packet(
            ethernet.ethernet(
                dst="00:00:00:00:01:00",
                src=source_mac,
                ethertype=0x88B5,
            ),
            b"unknown",
        )

        self.assertEqual(
            SourceIdentity(mac=source_mac, ipv4=None),
            parse_source_identity(data),
        )

    def test_ignores_lldp_and_multicast_source(self):
        ignored_packets = (
            serialize_packet(
                ethernet.ethernet(
                    dst="01:80:c2:00:00:0e",
                    src="00:00:00:00:00:01",
                    ethertype=ether_types.ETH_TYPE_LLDP,
                ),
            ),
            serialize_packet(
                ethernet.ethernet(
                    dst="00:00:00:00:01:00",
                    src="01:00:5e:00:00:01",
                    ethertype=ether_types.ETH_TYPE_IP,
                ),
            ),
        )

        for data in ignored_packets:
            with self.subTest(data=data):
                self.assertIsNone(parse_source_identity(data))

    def test_does_not_bind_spoofed_arp_mac_to_ipv4(self):
        data = serialize_packet(
            ethernet.ethernet(
                dst="ff:ff:ff:ff:ff:ff",
                src="00:00:00:00:00:01",
                ethertype=ether_types.ETH_TYPE_ARP,
            ),
            arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac="00:00:00:00:00:02",
                src_ip="10.0.0.1",
                dst_mac="00:00:00:00:00:00",
                dst_ip="10.0.0.100",
            ),
        )

        self.assertEqual(
            SourceIdentity(mac="00:00:00:00:00:01", ipv4=None),
            parse_source_identity(data),
        )

    def test_classifies_destination_mac(self):
        self.assertEqual(
            "broadcast",
            classify_destination("ff:ff:ff:ff:ff:ff"),
        )
        self.assertEqual(
            "multicast",
            classify_destination("01:00:5e:00:00:01"),
        )
        self.assertEqual(
            "unknown_unicast",
            classify_destination("00:00:00:00:01:00"),
        )


if __name__ == "__main__":
    unittest.main()
