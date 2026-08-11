import logging
import threading
import time

from app.analyzer_status import AnalyzerStatus
from app.backend_client import BackendClient
from app.config import load_config
from app.detection.port_scan import PortScanDetector
from app.detection.security_events import SecurityEventBuilder
from app.detection.server_behavior import ServerBehaviorDetector
from app.detection.traffic_stats import TrafficStatsBuilder
from app.outbox import DurableOutbox
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
    icmp_pps_threshold=config.icmp_pps_threshold,
    icmp_min_packet_count=config.icmp_min_packet_count,
    icmp_high_pps_threshold=config.icmp_high_pps_threshold,
    icmp_high_pps_multiplier=config.icmp_high_pps_multiplier,
    icmp_baseline_spike_multiplier=config.icmp_baseline_spike_multiplier,
    icmp_baseline_min_pps=config.icmp_baseline_min_pps,
    icmp_alert_cooldown_sec=config.icmp_alert_cooldown_sec,
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
    api_key=config.backend_api_key,
)
outbox = DurableOutbox(config.outbox_path)

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
    multi_target_threshold=config.port_scan_multi_target_threshold,
    high_unique_dst_port_threshold=config.port_scan_high_unique_dst_port_threshold,
    alert_cooldown_sec=config.port_scan_alert_cooldown_sec,
)

server_behavior_detector = ServerBehaviorDetector(
    protected_server_ips=set(config.protected_server_ips),
    egress_allowlist=set(config.server_egress_allowlist),
    fanout_window_sec=config.lateral_fanout_window_sec,
    fanout_unique_dst_threshold=(
        config.lateral_fanout_unique_dst_threshold
    ),
    fanout_connection_threshold=(
        config.lateral_fanout_connection_threshold
    ),
    alert_cooldown_sec=config.server_behavior_alert_cooldown_sec,
    volume_window_sec=config.exfil_volume_window_sec,
    outbound_bps_threshold=config.exfil_outbound_bps_threshold,
    outbound_baseline_multiplier=config.exfil_baseline_multiplier,
    outbound_sustained_windows=config.exfil_sustained_windows,
    beacon_window_sec=config.c2_beacon_window_sec,
    beacon_min_connections=config.c2_beacon_min_connections,
    beacon_min_interval_sec=config.c2_beacon_min_interval_sec,
    beacon_max_interval_sec=config.c2_beacon_max_interval_sec,
    beacon_max_jitter_ratio=config.c2_beacon_max_jitter_ratio,
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


# WINDOW_SEC마다 패킷 버퍼를 비우고 요약/탐지 결과를 백엔드로 전송
def analysis_loop():
    while True:
        try:
            time.sleep(WINDOW_SEC)

            # Outbox 저장이 끝날 때까지 원본 버퍼를 유지해 디스크 오류 시 재처리한다.
            with packets_lock:
                packets_snapshot = list(packets)

            # 포트 스캔 탐지는 원본 패킷 메타데이터의 TCP flag와 목적지 포트를 사용
            port_scan_alerts = port_scan_detector.detect(packets_snapshot)
            server_behavior_alerts = server_behavior_detector.detect(
                packets_snapshot,
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
                packets=packets_snapshot,
                port_scan_alerts=port_scan_alerts,
                server_behavior_alerts=server_behavior_alerts,
            )

            messages = [
                {
                    "path": "/api/analyzer/packet-summary",
                    "label": "packet summary",
                    "payload": packet_summary,
                },
                {
                    "path": "/api/analyzer/detection-summary",
                    "label": "traffic stats",
                    "payload": traffic_stats,
                },
            ]
            if security_events["events"]:
                messages.append(
                    {
                        "path": "/api/security/events",
                        "label": "security events",
                        "payload": security_events,
                    }
                )

            # 한 분석 윈도우의 결과를 원자적으로 저장한다.
            outbox.enqueue_batch(messages)

            # 저장 성공 후 snapshot만 제거하고 캡처 중 새로 들어온 패킷은 보존한다.
            with packets_lock:
                del packets[: len(packets_snapshot)]

        except Exception as exc:
            # 탐지 로직 예외로 분석 스레드가 죽지 않도록 오류 상태를 남기고 다음 윈도우로 넘어간다.
            error_message = f"analysis loop failed: {exc}"
            analyzer_status.mark_backend_failed(error_message)
            logger.exception(error_message)


def delivery_loop():
    while True:
        try:
            result = outbox.deliver_due(
                client=backend_client,
                batch_size=config.outbox_delivery_batch_size,
                retry_base_sec=config.outbox_retry_base_sec,
                retry_max_sec=config.outbox_retry_max_sec,
            )
            if result.delivered:
                analyzer_status.mark_summary_sent()
            if result.retried:
                analyzer_status.mark_backend_failed(
                    f"{result.retried} analyzer payload(s) queued for retry"
                )
            if result.dead_lettered:
                analyzer_status.mark_backend_failed(
                    f"{result.dead_lettered} analyzer payload(s) rejected"
                )
        except Exception as exc:
            error_message = f"outbox delivery failed: {exc}"
            analyzer_status.mark_backend_failed(error_message)
            logger.exception(error_message)

        time.sleep(config.outbox_delivery_poll_sec)


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

        threading.Thread(
            target=delivery_loop,
            daemon=True,
        ).start()

        # 메인 스레드는 패킷 캡처를 실행하고, 수신 패킷은 handle_packet으로 전달
        start_capture(INTERFACE, handle_packet)

    except PacketCaptureError as exc:
        analyzer_status.mark_capture_failed(str(exc))
        logger.error("packet capture failed: %s", exc)
