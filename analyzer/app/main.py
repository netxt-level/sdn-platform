import logging
import threading
import time

from app.analyzer_status import AnalyzerStatus
from app.backend_client import BackendClient
from app.config import load_config
from app.detection.port_scan import PortScanDetector
from app.detection.traffic_stats import TrafficStatsBuilder
from app.packet.capture import PacketCaptureError, start_capture
from app.packet.parser import parse_packet
from app.packet.summary import PacketSummaryBuilder
from app.security import DetectionConfig, SecurityRuntime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


config = load_config()
ANALYZER_ID = config.analyzer_id
INTERFACE = config.interface
WINDOW_SEC = config.window_sec
STATUS_INTERVAL_SEC = config.status_interval_sec
BACKEND_BASE_URL = config.backend_base_url

# 캡처 스레드와 분석 스레드가 공유하는 패킷 버퍼.
packets = []
packets_lock = threading.Lock()

# 백엔드 대시보드용 패킷 요약 생성기.
summary_builder = PacketSummaryBuilder(
    analyzer_id=ANALYZER_ID,
    window_sec=WINDOW_SEC,
)

# 기존 대시보드의 suspicious host 계산 흐름.
traffic_builder = TrafficStatsBuilder(
    analyzer_id=ANALYZER_ID,
)

# 보안 이벤트 생성 흐름. 현재 범위에서는 ARP_SPOOFING, PORT_SCAN, ICMP_FLOOD만 만든다.
security_runtime = SecurityRuntime(
    config=DetectionConfig(
        window_seconds=config.security_window_sec,
        icmp_pps_threshold=config.icmp_pps_threshold,
        port_scan_unique_ports=config.port_scan_unique_dst_port_threshold,
        rate_limit_pps=config.rate_limit_pps,
        gateway_ip=config.security_gateway_ip,
        gateway_mac=config.security_gateway_mac,
        trusted_ip_mac={
            config.security_gateway_ip: config.security_gateway_mac,
        },
    ),
    datapath_id="s1",
    event_cooldown_seconds=config.security_event_cooldown_sec,
)

backend_client = BackendClient(
    base_url=BACKEND_BASE_URL,
    timeout_sec=3.0,
)

analyzer_status = AnalyzerStatus(
    analyzer_id=ANALYZER_ID,
    interface=INTERFACE,
)

# 대시보드 의심 호스트 목록에 Port Scan을 같이 보여주기 위한 탐지기.
port_scan_detector = PortScanDetector(
    window_sec=config.port_scan_window_sec,
    unique_port_threshold=config.port_scan_unique_dst_port_threshold,
    syn_count_threshold=config.port_scan_syn_count_threshold,
    multi_target_window_sec=config.port_scan_multi_target_window_sec,
    multi_target_threshold=config.port_scan_multi_target_threshold,
    high_unique_dst_port_threshold=config.port_scan_high_unique_dst_port_threshold,
    alert_cooldown_sec=config.port_scan_alert_cooldown_sec,
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
        try:
            time.sleep(WINDOW_SEC)

            # 현재 분석 윈도우의 패킷만 snapshot으로 가져오고 버퍼는 비운다.
            with packets_lock:
                packets_snapshot = list(packets)
                packets.clear()

            # Port Scan은 TCP SYN 패턴을 별도로 보관해 대시보드 의심 호스트에도 반영한다.
            port_scan_hosts = port_scan_detector.detect(packets_snapshot)

            packet_summary = summary_builder.build_packet_summary(
                packets_snapshot,
            )

            traffic_stats = traffic_builder.build_traffic_stats(
                packet_summary=packet_summary,
                packets=packets_snapshot,
                extra_suspicious_hosts=port_scan_hosts,
            )

            # 보안 이벤트는 짧은 analyzer window를 보완하기 위해 SecurityRuntime의 rolling window에서 판단한다.
            security_output = security_runtime.analyze_snapshot(
                packets_snapshot,
                datapath_id="s1",
            )

            packet_summary_sent = backend_client.send_packet_summary(
                packet_summary
            )
            traffic_stats_sent = backend_client.send_traffic_stats(
                traffic_stats
            )

            security_events_sent = True
            if security_output.backend_payload["events"]:
                security_events_sent = backend_client.send_security_events(
                    security_output.backend_payload
                )

            if packet_summary_sent and traffic_stats_sent and security_events_sent:
                analyzer_status.mark_summary_sent()
            else:
                analyzer_status.mark_backend_failed(
                    "failed to send analyzer metrics"
                )

        except Exception as exc:
            error_message = f"analysis loop failed: {exc}"
            analyzer_status.mark_backend_failed(error_message)
            logger.exception(error_message)


def status_loop():
    while True:
        try:
            time.sleep(STATUS_INTERVAL_SEC)

            status_sent = backend_client.send_analyzer_status(
                analyzer_status.to_dict()
            )

            if not status_sent:
                analyzer_status.mark_backend_failed(
                    "failed to send analyzer status"
                )

        except Exception as exc:
            error_message = f"status loop failed: {exc}"
            analyzer_status.mark_backend_failed(error_message)
            logger.exception(error_message)


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
        logger.error("packet capture failed: %s", exc)
