import logging
import threading
import time

from app.analyzer_status import AnalyzerStatus
from app.backend_client import BackendClient
from app.config import load_config
from app.detection.flood import FloodThresholds, IcmpFloodDetector, UdpFloodDetector
from app.detection.port_scan import PortScanDetector
from app.detection.security_events import (
    PendingSecurityEventQueue,
    SecurityEventBuilder,
)
from app.detection.syn_flood import SynFloodDetector
from app.detection.traffic_stats import TrafficStatsBuilder
from app.packet.capture import PacketCaptureError, start_capture
from app.packet.parser import parse_packet
from app.packet.summary import PacketSummaryBuilder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


# 실행 환경에 따라 바뀌는 분석 서버 설정값
config = load_config()
ANALYZER_ID = config.analyzer_id
INTERFACE = config.interface
WINDOW_SEC = config.window_sec
STATUS_INTERVAL_SEC = config.status_interval_sec
BACKEND_BASE_URL = config.backend_base_url

# 아래 객체들은 캡처, 분석, 전송 루프가 공유하는 런타임 구성요소다.
# 캡처 스레드가 쌓고 분석 스레드가 비우는 공유 패킷 버퍼
packets = []
packets_lock = threading.Lock()
pending_security_events = PendingSecurityEventQueue(max_size=500)

# 패킷 목록을 백엔드 전송용 packet-summary payload로 변환
summary_builder = PacketSummaryBuilder(
    analyzer_id=ANALYZER_ID,
    window_sec=WINDOW_SEC,
)

# packet-summary와 원본 패킷 목록을 기반으로 detection-summary payload 생성
traffic_builder = TrafficStatsBuilder(
    analyzer_id=ANALYZER_ID,
)

security_event_builder = SecurityEventBuilder(
    analyzer_id=ANALYZER_ID,
    event_dedup_window_sec=config.event_dedup_window_sec,
    rate_limit_priority=config.rate_limit_priority,
    rate_limit_idle_timeout=config.rate_limit_idle_timeout,
    rate_limit_hard_timeout=config.rate_limit_hard_timeout,
    rate_limit_pps=config.rate_limit_pps,
    drop_priority=config.drop_priority,
    drop_idle_timeout=config.drop_idle_timeout,
    drop_hard_timeout=config.drop_hard_timeout,
)

# 백엔드 API 호출을 담당하는 클라이언트
backend_client = BackendClient(
    base_url=BACKEND_BASE_URL,
    timeout_sec=3.0,
)

# 분석 서버의 캡처 상태, 백엔드 연결 상태, 최근 처리 시각을 관리
analyzer_status = AnalyzerStatus(
    analyzer_id=ANALYZER_ID,
    interface=INTERFACE,
)

# TCP SYN 기반 포트 스캔 의심 호스트 탐지기
port_scan_detector = PortScanDetector(
    window_sec=config.port_scan_window_sec,
    unique_port_threshold=config.port_scan_unique_dst_port_threshold,
    syn_count_threshold=config.port_scan_syn_count_threshold,
    multi_target_window_sec=config.port_scan_multi_target_window_sec,
    high_unique_dst_port_threshold=config.port_scan_high_unique_dst_port_threshold,
    horizontal_target_threshold=config.port_scan_horizontal_target_threshold,
    alert_cooldown_sec=config.port_scan_alert_cooldown_sec,
)

# ICMP Flood는 ping 요청이 짧은 시간에 과도하게 몰리는지 확인한다.
icmp_flood_detector = IcmpFloodDetector(
    FloodThresholds(
        pps=config.icmp_pps_threshold,
        high_pps=config.icmp_high_pps_threshold,
        critical_pps=config.icmp_critical_pps_threshold,
        minimum_packets=config.icmp_min_packet_count,
    )
)

# UDP Flood는 패킷 수와 트래픽 양을 같이 보며, 단순 PPS 기준의 한계를 줄인다.
udp_flood_detector = UdpFloodDetector(
    FloodThresholds(
        pps=config.udp_pps_threshold,
        high_pps=config.udp_high_pps_threshold,
        critical_pps=config.udp_critical_pps_threshold,
        minimum_packets=config.udp_min_packet_count,
        bps=config.udp_bps_threshold,
        high_bps=config.udp_high_bps_threshold,
        critical_bps=config.udp_critical_bps_threshold,
    )
)

# SYN Flood는 Port Scan과 겹치지 않도록 단일 서비스 집중 패턴만 본다.
syn_flood_detector = SynFloodDetector(
    pps_threshold=config.syn_pps_threshold,
    high_pps_threshold=config.syn_high_pps_threshold,
    critical_pps_threshold=config.syn_critical_pps_threshold,
    max_unique_ports=config.syn_max_unique_ports,
    minimum_syn_count=config.syn_min_count,
)


# packet_capture가 패킷을 하나 받을 때마다 호출하는 callback
def handle_packet(packet):
    metadata = parse_packet(packet)

    # 파싱할 수 없는 패킷은 집계 대상에서 제외
    if metadata is None:
        return

    analyzer_status.mark_packet_received()

    # 캡처 callback과 분석 루프가 동시에 접근하므로 lock으로 보호
    with packets_lock:
        packets.append(metadata)


def queue_security_events(events):
    """백엔드 전송 전 보안 이벤트를 메모리 대기 큐에 저장한다."""

    dropped_events = pending_security_events.add(events)
    if dropped_events:
        security_event_builder.forget_events(dropped_events)


def send_pending_security_events(timestamp):
    """전송 실패로 남아 있는 보안 이벤트를 다음 분석 주기에 다시 전송한다."""

    if len(pending_security_events) == 0:
        return True

    payload = pending_security_events.payload(
        timestamp=timestamp,
        analyzer_id=ANALYZER_ID,
    )

    try:
        sent = backend_client.send_security_events(payload)
    except Exception as exc:
        analyzer_status.mark_backend_failed("failed to send security events")
        logger.exception("security events 전송 중 예외가 발생했습니다: %s", exc)
        return False

    if sent:
        pending_security_events.clear()
        return True

    analyzer_status.mark_backend_failed("failed to send security events")
    return False


# WINDOW_SEC마다 패킷 버퍼를 비우고 요약/탐지 결과를 백엔드로 전송
def analysis_loop():
    while True:
        try:
            time.sleep(WINDOW_SEC)

            # 현재 윈도우의 패킷만 분석하기 위해 snapshot을 만든 뒤 버퍼를 초기화
            with packets_lock:
                packets_snapshot = list(packets)
                packets.clear()

            # 포트 스캔 탐지는 원본 패킷 메타데이터의 TCP flag와 목적지 포트를 사용
            port_scan_alerts = port_scan_detector.detect(packets_snapshot)
            security_detections = []
            security_detections.extend(port_scan_alerts)
            security_detections.extend(
                icmp_flood_detector.detect(packets_snapshot, WINDOW_SEC)
            )
            security_detections.extend(
                udp_flood_detector.detect(packets_snapshot, WINDOW_SEC)
            )
            security_detections.extend(
                syn_flood_detector.detect(packets_snapshot, WINDOW_SEC)
            )

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
                detections=security_detections,
            )
            queue_security_events(security_events["events"])

            # 패킷 요약과 탐지 요약은 각각 별도 API로 전송
            packet_summary_sent = backend_client.send_packet_summary(
                packet_summary
            )

            traffic_stats_sent = backend_client.send_traffic_stats(
                traffic_stats
            )

            security_events_sent = send_pending_security_events(
                security_events["timestamp"]
            )

            # 요약과 보안 이벤트가 모두 전송된 경우에만 백엔드 연결 상태를 정상으로 표시
            if packet_summary_sent and traffic_stats_sent and security_events_sent:
                analyzer_status.mark_summary_sent()
            else:
                analyzer_status.mark_backend_failed(
                    "failed to send analyzer metrics or security events"
                )

        except Exception as exc:
            # 탐지 로직 예외로 분석 스레드가 죽지 않도록 오류 상태를 남기고 다음 윈도우로 넘어간다.
            error_message = f"analysis loop failed: {exc}"
            analyzer_status.mark_backend_failed(error_message)
            logger.exception(error_message)


# STATUS_INTERVAL_SEC마다 분석 서버의 현재 상태를 백엔드로 보고
def status_loop():
    while True:
        try:
            time.sleep(STATUS_INTERVAL_SEC)

            status_sent = backend_client.send_analyzer_status(
                analyzer_status.to_dict()
            )

            if not status_sent:
                # 상태 전송 실패도 다음 상태 보고에 반영되도록 백엔드 연결 실패로 표시한다.
                analyzer_status.mark_backend_failed(
                    "failed to send analyzer status"
                )

        except Exception as exc:
            # 상태 전송 스레드도 예외 한 번으로 종료되지 않게 보호한다.
            error_message = f"status loop failed: {exc}"
            analyzer_status.mark_backend_failed(error_message)
            logger.exception(error_message)


if __name__ == "__main__":
    try:
        analyzer_status.mark_capture_started()

        # 분석과 상태 보고는 캡처가 막히지 않도록 daemon thread에서 수행
        threading.Thread(
            target=analysis_loop,
            daemon=True,
        ).start()

        threading.Thread(
            target=status_loop,
            daemon=True,
        ).start()

        # 메인 스레드는 패킷 캡처를 실행하고, 수신 패킷은 handle_packet으로 전달
        start_capture(INTERFACE, handle_packet)

    except PacketCaptureError as exc:
        analyzer_status.mark_capture_failed(str(exc))
        logger.error("packet capture failed: %s", exc)
