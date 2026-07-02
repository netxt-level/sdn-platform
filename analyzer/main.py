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

# 실행 환경에 따라 바뀌는 분석 서버 설정값
ANALYZER_ID = os.getenv("ANALYZER_ID", "analyzer-1")
INTERFACE = os.getenv("ANALYZER_INTERFACE", "en0")
WINDOW_SEC = int(os.getenv("ANALYZER_WINDOW_SEC", "1"))
STATUS_INTERVAL_SEC = int(os.getenv("ANALYZER_STATUS_INTERVAL_SEC", "5"))
BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL", "http://127.0.0.1:8000")

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
    window_sec=5,
    unique_port_threshold=20,
    alert_cooldown_sec=30,
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

            # 현재 윈도우의 패킷만 분석하기 위해 snapshot을 만든 뒤 버퍼를 초기화
            with packets_lock:
                packets_snapshot = list(packets)
                packets.clear()

            # 포트 스캔 탐지는 원본 패킷 메타데이터의 TCP flag와 목적지 포트를 사용
            port_scan_hosts = port_scan_detector.detect(packets_snapshot)

            packet_summary = summary_builder.build_packet_summary(
                packets_snapshot,
            )

            # traffic stats에는 DoS 의심 호스트와 포트 스캔 의심 호스트가 함께 포함
            traffic_stats = traffic_builder.build_traffic_stats(
                packet_summary=packet_summary,
                packets=packets_snapshot,
                extra_suspicious_hosts=port_scan_hosts,
            )

            # 패킷 요약과 탐지 요약은 각각 별도 API로 전송
            packet_summary_sent = backend_client.send_packet_summary(
                packet_summary
            )

            traffic_stats_sent = backend_client.send_traffic_stats(
                traffic_stats
            )

            # 두 요약 전송이 모두 성공한 경우에만 백엔드 연결 상태를 정상으로 표시
            if packet_summary_sent and traffic_stats_sent:
                analyzer_status.mark_summary_sent()
            else:
                analyzer_status.mark_backend_failed(
                    "failed to send analyzer metrics"
                )

        except Exception as exc:
            error_message = f"analysis loop failed: {exc}"
            analyzer_status.mark_backend_failed(error_message)
            print(f"[Analyzer] {error_message}")


# STATUS_INTERVAL_SEC마다 분석 서버의 현재 상태를 백엔드로 보고
def status_loop():
    while True:
        time.sleep(STATUS_INTERVAL_SEC)

        backend_client.send_analyzer_status(
            analyzer_status.to_dict()
        )


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
        print(exc)
