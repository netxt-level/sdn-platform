import os
import threading
import time

from analyzer_status import AnalyzerStatus
from backend_client import BackendClient
from packet_capture import PacketCaptureError, start_capture
from packet_parser import parse_packet
from packet_summary import PacketSummaryBuilder
from traffic_stats import TrafficStatsBuilder
from port_scan_detector import PortScanDetector

INTERFACE = os.getenv("INTERFACE", "en0")
ANALYZER_ID = os.getenv("ANALYZER_ID", "analyzer-1")
WINDOW_SEC = int(os.getenv("WINDOW_SEC", "1"))
STATUS_INTERVAL_SEC = int(os.getenv("STATUS_INTERVAL_SEC", "5"))
BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL", "http://127.0.0.1:8000")

packets = []
packets_lock = threading.Lock()

summary_builder = PacketSummaryBuilder(
    analyzer_id=ANALYZER_ID,
    window_sec=WINDOW_SEC,
)

traffic_builder = TrafficStatsBuilder(
    analyzer_id=ANALYZER_ID,
)

backend_client = BackendClient(
    base_url=BACKEND_BASE_URL,
    timeout_sec=3.0,
)

analyzer_status = AnalyzerStatus(
    analyzer_id=ANALYZER_ID,
    interface=INTERFACE,
)

port_scan_detector = PortScanDetector(
    window_sec=5,
    unique_port_threshold=20,
    alert_cooldown_sec=30,
)

def handle_packet(packet):
    metadata = parse_packet(packet)

    if metadata is None:
        return

    analyzer_status.mark_packet_received()

    with packets_lock:
        packets.append(metadata)

def analysis_loop():
    while True:
        time.sleep(WINDOW_SEC)

        with packets_lock:
            packets_snapshot = list(packets)
            packets.clear()

        port_scan_hosts = port_scan_detector.detect(packets_snapshot)

        packet_summary = summary_builder.build_packet_summary(
            packets_snapshot,
        )

        traffic_stats = traffic_builder.build_traffic_stats(
            packet_summary=packet_summary,
            packets=packets_snapshot,
            extra_suspicious_hosts=port_scan_hosts,
        )

        packet_summary_sent = backend_client.send_packet_summary(
            packet_summary
        )

        traffic_stats_sent = backend_client.send_traffic_stats(
            traffic_stats
        )

        if packet_summary_sent and traffic_stats_sent:
            analyzer_status.mark_summary_sent()
        else:
            analyzer_status.mark_backend_failed(
                "failed to send analyzer metrics"
            )

def status_loop():
    while True:
        time.sleep(STATUS_INTERVAL_SEC)

        backend_client.send_analyzer_status(
            analyzer_status.to_dict()
        )

if __name__ == "__main__":
    try:
        analyzer_status.mark_capture_started()

        threading.Thread(
            target=analysis_loop,
            daemon=True,
        ).start()

        threading.Thread(
            target=status_loop,
            daemon=True,
        ).start()

        start_capture(INTERFACE, handle_packet)

    except PacketCaptureError as exc:
        analyzer_status.mark_capture_failed(str(exc))
        print(exc)
