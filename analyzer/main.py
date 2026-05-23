import threading
import time

from packet_capture import start_capture, PacketCaptureError
from packet_parser import parse_packet
from packet_summary import PacketSummaryBuilder

ANALYZER_INTERFACE = "en0"
BACKEND_BASE_URL = "http://127.0.0.1:8000"

packets = []
packets_lock = threading.Lock()

summary_builder = PacketSummaryBuilder(
    analyzer_id = "analyzer-1",
    window_sec = 1,
)

def handle_packet(packet):
    metadata = parse_packet(packet)
    
    if metadata is None:
        return
    
    with packets_lock:
        packets.append(metadata)

def summary_loop():
    while True:
        time.sleep(summary_builder.window_sec)

        with packets_lock:
            packets_snapshot = list(packets)
            packets.clear()

        summary = summary_builder.build_packet_summary(packets_snapshot)

        if summary["total_packets"] > 0:
            print(summary)

if __name__ == "__main__":
    try:
        threading.Thread(target=summary_loop, daemon=True).start()
        start_capture("en0", handle_packet)

    except PacketCaptureError as exc:
        print(exc)