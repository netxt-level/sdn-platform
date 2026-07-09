import logging
import threading
import time

from app.analyzer_status import AnalyzerStatus
from app.backend_client import BackendClient
from app.config import load_config
from app.detection.port_scan import PortScanDetector
from app.detection.security_events import SecurityEventBuilder
from app.detection.traffic_stats import TrafficStatsBuilder
from app.packet.capture import PacketCaptureError, start_capture
from app.packet.parser import parse_packet
from app.packet.summary import PacketSummaryBuilder

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

security_event_builder = SecurityEventBuilder(
    analyzer_id=ANALYZER_ID,
    gateway_ip=config.security_gateway_ip,
    gateway_mac=config.security_gateway_mac,
    arp_drop_priority=config.arp_drop_priority,
    arp_drop_idle_timeout=config.arp_drop_idle_timeout,
    arp_drop_hard_timeout=config.arp_drop_hard_timeout,
    icmp_pps_threshold=config.icmp_pps_threshold,
    icmp_min_packet_count=config.icmp_min_packet_count,
    icmp_high_pps_threshold=config.icmp_high_pps_threshold,
    icmp_high_pps_multiplier=config.icmp_high_pps_multiplier,
    event_dedup_window_sec=config.event_dedup_window_sec,
    rate_limit_priority=config.rate_limit_priority,
    rate_limit_idle_timeout=config.rate_limit_idle_timeout,
    rate_limit_hard_timeout=config.rate_limit_hard_timeout,
    rate_limit_pps=config.rate_limit_pps,
)

# 백엔드 API 호출을 담당하는 클라이언트
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

            # 포트 스캔 탐지는 원본 패킷 메타데이터의 TCP flag와 목적지 포트를 사용
            port_scan_alerts = port_scan_detector.detect(packets_snapshot)

            packet_summary = summary_builder.build_packet_summary(
                packets_snapshot,
            )

            # traffic stats는 네트워크 전체 트래픽 상태만 포함한다.
            traffic_stats = traffic_builder.build_traffic_stats(
                packet_summary=packet_summary,
                packets=packets_snapshot,
            )

            # 보안 탐지 결과는 traffic stats와 분리해 공통 SecurityEvent 형식으로 전송한다.
            security_events = security_event_builder.build_security_events(
                packet_summary=packet_summary,
                packets=packets_snapshot,
                port_scan_alerts=port_scan_alerts,
            )

            packet_summary_sent = backend_client.send_packet_summary(
                packet_summary
            )
            traffic_stats_sent = backend_client.send_traffic_stats(
                traffic_stats
            )

            security_events_sent = True
            if security_events["events"]:
                security_events_sent = backend_client.send_security_events(
                    security_events
                )

            # 보안 이벤트가 있을 때는 해당 전송까지 성공해야 연결 상태를 정상으로 본다.
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
