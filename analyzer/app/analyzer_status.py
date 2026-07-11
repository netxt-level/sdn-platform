from datetime import datetime, timezone


class AnalyzerStatus:
    """Analyzer의 실행 상태와 전송 안정성 지표를 상태 API payload로 만든다."""

    def __init__(self, analyzer_id: str, interface: str):
        self.analyzer_id = analyzer_id
        self.interface = interface

        self.status = "running"
        self.capture_active = False
        self.backend_connected = False

        self.last_packet_at = None
        self.last_summary_sent_at = None
        self.error_message = None

        self.pending_security_event_count = 0
        self.dropped_security_event_count = 0
        self.packet_buffer_dropped_count = 0
        self.last_security_event_send_failure = None

    def mark_capture_started(self):
        self.capture_active = True
        self.status = "running"
        self.error_message = None

    def mark_capture_failed(self, error_message: str):
        self.capture_active = False
        self.status = "error"
        self.error_message = error_message

    def mark_packet_received(self):
        self.last_packet_at = self._now_iso()

    def mark_summary_sent(self):
        self.backend_connected = True
        self.last_summary_sent_at = self._now_iso()
        self.error_message = None

    def mark_backend_failed(self, error_message: str):
        self.backend_connected = False
        self.error_message = error_message

    def mark_security_event_send_failed(self):
        self.last_security_event_send_failure = self._now_iso()

    def update_runtime_metrics(
        self,
        *,
        pending_security_event_count: int,
        dropped_security_event_count: int,
        packet_buffer_dropped_count: int,
    ) -> None:
        self.pending_security_event_count = pending_security_event_count
        self.dropped_security_event_count = dropped_security_event_count
        self.packet_buffer_dropped_count = packet_buffer_dropped_count

    def to_dict(self) -> dict:
        return {
            "timestamp": self._now_iso(),
            "analyzer_id": self.analyzer_id,
            "status": self.status,
            "interface": self.interface,
            "capture_active": self.capture_active,
            "backend_connected": self.backend_connected,
            "last_packet_at": self.last_packet_at,
            "last_summary_sent_at": self.last_summary_sent_at,
            "error_message": self.error_message,
            "pending_security_event_count": self.pending_security_event_count,
            "dropped_security_event_count": self.dropped_security_event_count,
            "packet_buffer_dropped_count": self.packet_buffer_dropped_count,
            "last_security_event_send_failure": (
                self.last_security_event_send_failure
            ),
        }

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()
