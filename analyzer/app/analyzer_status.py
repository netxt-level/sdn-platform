from datetime import datetime, timezone

# 분석 서버의 현재 실행 상태를 관리하는 클래스
class AnalyzerStatus:
    def __init__(self, analyzer_id: str, interface: str):
        self.analyzer_id = analyzer_id  # 패킷 전송 스위치 ID
        self.interface = interface      # 패킷 캡처에 사용하는 네트워크 인터페이스 이름

        self.status = "running"         # 분석 서버의 전체 상태
        self.capture_active = False     # 패킷 캡처 활성화 여부
        self.backend_connected = False  # 백엔드 서버와 정상 통신 여부

        self.last_packet_at = None          # 마지막 패킷 수신 시각
        self.last_summary_sent_at = None    # 마지막 패킷 요약 정보 수신 시각
        self.error_message = None           # 오류 발생 시 저장할 에러 메세지

    # 패킷 캡처 정상 시작 시 호출하는 함수
    def mark_capture_started(self):
        self.capture_active = True  # 캡처 활성 상태로 변경
        self.status = "running"     # 분석 서버 상태를 running으로 설정
        self.error_message = None   # 이전 에러 메세지 초기화

    # 패킷 캡처 시작 또는 실행 도중 실패 시 호출하는 함수
    def mark_capture_failed(self, error_message: str):
        self.capture_active = False         # 켑처 비활성 상태로 변경
        self.status = "error"               # 분석 서버 상태를 error로 설정
        self.error_message = error_message  # 발생한 에러 메세지 저장

    # 패킷이 정상적으로 수신 시 호출하는 함수
    def mark_packet_received(self):
        self.last_packet_at = self._now_iso()   # 마지막 패킷 수신 시각 갱신

    # 패킷 요약 정보 또는 트래픽 통계가 백엔드에 정상 전송되었을 때 호출하는 함수
    def mark_summary_sent(self):
        self.backend_connected = True                   # 백엔드 연결 상태를 정상으로 표시
        self.last_summary_sent_at = self._now_iso()     # 마지막 요약 정보 전송 시각 갱신
        self.error_message = None                       # 이전 에러 메세지 초기화

    # 백엔드 서버 전송에 실패했을 때 호출하는 함수
    def mark_backend_failed(self, error_message: str):
        self.backend_connected = False          # 백엔드 연결 상태를 실패로 표시
        self.error_message = error_message      # 발생한 에러 메세지 저장

    def to_dict(self) -> dict:
        return {
            "timestamp": self._now_iso(),                       # 상태 정보 생성 시각
            "analyzer_id": self.analyzer_id,                    # 패킷 전송 스위치 ID
            "status": self.status,                              # 분석 서버 상태
            "interface": self.interface,                        # 사용 중인 네트워크 인터페이스
            "capture_active": self.capture_active,              # 패킷 캡처 활성 여부
            "backend_connected": self.backend_connected,        # 백엔드 연결 여부
            "last_packet_at": self.last_packet_at,              # 마지막 패킷 수신 시각
            "last_summary_sent_at": self.last_summary_sent_at,  # 마지막 요약 정보 생성 시각
            "error_message": self.error_message,                # 에러 메세지
        }

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()
