from packet_capture import start_capture, PacketCaptureError
from packet_parser import parse_packet

def handle_packet(packet):
    metadata = parse_packet(packet)
    print(metadata)
    
if __name__ == "__main__":
    try:
        start_capture("en0", handle_packet)
    except PacketCaptureError as exc:
        print(exc)