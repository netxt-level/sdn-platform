from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether


def parse_packet(packet):
    """Scapy 패킷을 탐지기가 사용하는 공통 메타데이터로 변환한다."""

    metadata = {
        "timestamp": packet.time,
        "packet_size": len(packet),
    }

    if Ether in packet:
        metadata["src_mac"] = packet[Ether].src
        metadata["dst_mac"] = packet[Ether].dst

    if IP in packet:
        metadata["src_ip"] = packet[IP].src
        metadata["dst_ip"] = packet[IP].dst
    elif ARP in packet:
        metadata["src_ip"] = packet[ARP].psrc
        metadata["dst_ip"] = packet[ARP].pdst

    if TCP in packet:
        metadata["protocol"] = "TCP"
        metadata["src_port"] = packet[TCP].sport
        metadata["dst_port"] = packet[TCP].dport
        metadata["tcp_flags"] = str(packet[TCP].flags)

    elif UDP in packet:
        metadata["protocol"] = "UDP"
        metadata["src_port"] = packet[UDP].sport
        metadata["dst_port"] = packet[UDP].dport

    elif ICMP in packet:
        metadata["protocol"] = "ICMP"
        # ICMP Flood 탐지에서 Echo Request만 구분할 수 있도록 type/code를 보존한다.
        metadata["icmp_type"] = packet[ICMP].type
        metadata["icmp_code"] = packet[ICMP].code

    elif ARP in packet:
        metadata["protocol"] = "ARP"

    else:
        metadata["protocol"] = "OTHER"

    return metadata
