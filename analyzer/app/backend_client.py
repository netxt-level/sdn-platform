import logging

import requests

logger = logging.getLogger(__name__)


class BackendClient:
    """Analyzer가 만든 요약과 보안 이벤트를 Backend FastAPI 서버로 전송한다."""

    def __init__(self, base_url: str, timeout_sec: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_sec = timeout_sec

    def send_packet_summary(self, packet_summary: dict) -> bool:
        return self._post(
            path="/api/analyzer/packet-summary",
            payload=packet_summary,
            label="packet summary",
        )

    def send_traffic_stats(self, traffic_stats: dict) -> bool:
        return self._post(
            path="/api/analyzer/detection-summary",
            payload=traffic_stats,
            label="traffic stats",
        )

    def send_security_events(self, security_events: dict) -> bool:
        return self._post(
            path="/api/security/events",
            payload=security_events,
            label="security events",
        )

    def send_analyzer_status(self, analyzer_status: dict) -> bool:
        return self._post(
            path="/api/analyzer/status",
            payload=analyzer_status,
            label="analyzer status",
        )

    def _post(self, path: str, payload: dict, label: str) -> bool:
        """전송 실패를 예외로 퍼뜨리지 않고 False로 바꿔 분석 루프를 유지한다."""

        url = f"{self.base_url}{path}"

        try:
            response = requests.post(
                url,
                json=payload,
                timeout=self.timeout_sec,
            )
            response.raise_for_status()
            return True

        except requests.exceptions.ConnectionError:
            logger.warning("%s 전송 실패: 서버에 연결할 수 없습니다.", label)
            return False

        except requests.exceptions.Timeout:
            logger.warning("%s 전송 실패: 요청 시간이 초과되었습니다.", label)
            return False

        except requests.exceptions.HTTPError as exc:
            status_code = (
                exc.response.status_code
                if exc.response is not None
                else "unknown"
            )
            logger.warning(
                "%s 전송 실패: HTTP %s 응답을 받았습니다.",
                label,
                status_code,
            )
            return False

        except requests.exceptions.RequestException:
            logger.warning("%s 전송 실패: 요청 처리 중 오류가 발생했습니다.", label)
            return False
