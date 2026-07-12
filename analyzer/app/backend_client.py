import logging
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BackendResult:
    success: bool
    status_code: int | None = None
    error: str | None = None

    def __bool__(self) -> bool:
        return self.success


class BackendClient:
    """Analyzer가 만든 요약과 보안 이벤트를 Backend FastAPI 서버로 전송한다."""

    def __init__(
        self,
        base_url: str,
        timeout_sec: float = 3.0,
        api_key: str = "",
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_sec = timeout_sec
        self.headers = {"X-API-Key": api_key} if api_key else None

    def send_packet_summary(self, packet_summary: dict) -> BackendResult:
        return self._post(
            path="/api/analyzer/packet-summary",
            payload=packet_summary,
            label="packet summary",
        )

    def send_traffic_stats(self, traffic_stats: dict) -> BackendResult:
        return self._post(
            path="/api/analyzer/detection-summary",
            payload=traffic_stats,
            label="traffic stats",
        )

    def send_security_events(self, security_events: dict) -> BackendResult:
        return self._post(
            path="/api/security/events",
            payload=security_events,
            label="security events",
        )

    def send_analyzer_status(self, analyzer_status: dict) -> BackendResult:
        return self._post(
            path="/api/analyzer/status",
            payload=analyzer_status,
            label="analyzer status",
        )

    def _post(self, path: str, payload: dict, label: str) -> BackendResult:
        """전송 결과와 HTTP 상태 코드를 요청별 BackendResult로 반환한다."""

        url = f"{self.base_url}{path}"

        try:
            response = requests.post(
                url,
                json=payload,
                headers=self.headers,
                timeout=self.timeout_sec,
            )
            response.raise_for_status()
            return BackendResult(
                success=True,
                status_code=getattr(response, "status_code", None),
            )

        except requests.exceptions.ConnectionError:
            logger.warning("%s 전송 실패: 서버에 연결할 수 없습니다.", label)
            return BackendResult(success=False, error="connection_error")

        except requests.exceptions.Timeout:
            logger.warning("%s 전송 실패: 요청 시간이 초과되었습니다.", label)
            return BackendResult(success=False, error="timeout")

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
            return BackendResult(
                success=False,
                status_code=(
                    exc.response.status_code
                    if exc.response is not None
                    else None
                ),
                error="http_error",
            )

        except requests.exceptions.RequestException:
            logger.warning("%s 전송 실패: 요청 처리 중 오류가 발생했습니다.", label)
            return BackendResult(success=False, error="request_error")
