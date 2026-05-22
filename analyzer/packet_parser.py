from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

# 캡처된 패킷에서 필요한 메타데이터를 추출하는 함수
def parse_packet(packet):
    # 모든 종류의 패킷에서 추출할 기본 정보 저장
    metadata = {
        "timestamp": packet.time,   # 패킷이 캡처된 시간
        "packet_size": len(packet), # 전체 패킷 크기
        "payload_size": 0,          # 실제 데이터(payload) 크기
    }
    
    # 패킷에 Ethernet 계층이 포함되어 있는지 확인
    if Ether in packet:
        metadata["src_mac"] = packet[Ether].src # 출발지 MAC 주소
        metadata["dst_mac"] = packet[Ether].dst # 목적지 MAC 주소
    
    # 패킷에 IP 계층이 포함되어 있는지 확인    
    if IP in packet:
        metadata["src_ip"] = packet[IP].src # 출발지 IP 주소
        metadata["dst_ip"] = packet[IP].dst # 도착지 IP 주소
    
    # 패킷이 TCP 프로토콜을 사용하는 경우
    if TCP in packet:
        metadata["protocol"] = "TCP"                    # 프로토콜 종류 (TCP)
        metadata["src_port"] = packet[TCP].sport        # 출발지 포트 번호
        metadata["dst_port"] = packet[TCP].dport        # 목적지 포트 번호
        
        # TCP 플래그 정보 (SYN, ACK, FIN, RST 등)
        metadata["tcp_flags"] = str(packet[TCP].flags)
        
        # TCP Payload 크기 계산 (실제 데이터 부분 크기)
        metadata["payload_size"] = len(bytes(packet[TCP].payload))

    # 패킷이 UDP 프로토콜을 사용하는 경우
    elif UDP in packet:
        metadata["protocol"] = "UDP"                # 프로토콜 종류 (UDP)
        metadata["src_port"] = packet[UDP].sport    # 출발지 포트 번호
        metadata["dst_port"] = packet[UDP].dport    # 목적지 포트 번호
        
        # UDP Payload 크기 계산 (실제 데이터 부분 크기)
        metadata["payload_size"] = len(bytes(packet[UDP].payload))

    # 패킷이 ICMP 프로토콜을 사용하는 경우
    elif ICMP in packet:
        metadata["protocol"] = "ICMP"   # 프로토콜 종류 (ICMP)
        
        # ICMP Payload 크기 계산 (실제 데이터 부분 크기)
        metadata["payload_size"] = len(bytes(packet[ICMP].payload))
    
    # 패킷이 TCP, UDP, ICMP 프로토콜에 해당하지 않는 경우    
    else:
        
        # 알 수 없는 프로토콜로 표시
        # ex) ARP, IPv6, 기타 프로토콜 등
        metadata["protocol"] = "UNKNOWN"
    
    # 추출한 메타데이터 반환    
    return metadata