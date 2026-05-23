import threading
import time

from packet_capture import start_capture, PacketCaptureError
from packet_parser import parse_packet
from packet_summary import PacketSummaryBuilder
from traffic_stats import TrafficStatsBuilder


INTERFACE = "en0"
ANALYZER_ID = "analyzer-1"
WINDOW_SEC = 1

packets = []
packets_lock = threading.Lock()

summary_builder = PacketSummaryBuilder(
    analyzer_id=ANALYZER_ID,
    window_sec=WINDOW_SEC,
)

traffic_builder = TrafficStatsBuilder(
    analyzer_id=ANALYZER_ID,
)


def handle_packet(packet):
    metadata = parse_packet(packet)

    if metadata is None:
        return

    with packets_lock:
        packets.append(metadata)


def analysis_loop():
    while True:
        time.sleep(WINDOW_SEC)

        with packets_lock:
            packets_snapshot = list(packets)
            packets.clear()

        packet_summary = summary_builder.build_packet_summary(
            packets_snapshot
        )

        traffic_stats = traffic_builder.build_traffic_stats(
            packet_summary=packet_summary,
            packets=packets_snapshot,
        )

        # print("packet_summary:", packet_summary)
        # print("traffic_stats:", traffic_stats)


if __name__ == "__main__":
    try:
        threading.Thread(
            target=analysis_loop,
            daemon=True,
        ).start()

        start_capture(INTERFACE, handle_packet)

    except PacketCaptureError as exc:
        print(exc)