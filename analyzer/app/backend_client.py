import logging

import requests

logger = logging.getLogger(__name__)


# 분석 서버가 만든 payload를 백엔드 FastAPI 서버로 전송하는 HTTP 클라이언트
class BackendClient:
    def __init__(self, base_url: str, timeout_sec: float = 3.0):
        # base_url 끝의 /를 제거해 path를 붙일 때 //가 생기지 않게 한다.
        self.base_url = base_url.rstrip("/")
        self.timeout_sec = timeout_sec

    # 패킷 요약 데이터를 백엔드에 저장하고 WebSocket으로 broadcast하게 전송
    def send_packet_summary(self, packet_summary: dict) -> bool:
        return self._post(
            path="/api/analyzer/packet-summary",
            payload=packet_summary,
            label="packet summary",
        )

    # 네트워크 상태와 의심 호스트 탐지 결과를 백엔드에 전송
    def send_traffic_stats(self, traffic_stats: dict) -> bool:
        return self._post(
            path="/api/analyzer/detection-summary",
            payload=traffic_stats,
            label="traffic stats",
        )

    # 분석 서버 실행/캡처/백엔드 연결 상태를 백엔드에 전송
    def send_analyzer_status(self, analyzer_status: dict) -> bool:
        return self._post(
            path="/api/analyzer/status",
            payload=analyzer_status,
            label="analyzer status",
        )

    # 모든 전송 API가 공유하는 POST 처리 함수
    def _post(self, path: str, payload: dict, label: str) -> bool:
        # 전송 실패는 예외를 밖으로 던지지 않고 False로 반환해 분석 루프를 계속 유지한다.
        url = f"{self.base_url}{path}"

        try:
            # timeout을 짧게 두어 백엔드 장애가 분석 루프를 오래 막지 않게 한다.
            response = requests.post(
                url,
                json=payload,
                timeout=self.timeout_sec,
            )
            # 4xx/5xx 응답은 예외로 변환해 실패로 처리
            response.raise_for_status()
            return True

        # 백엔드 서버가 내려가 있거나 네트워크 연결 자체가 실패한 경우
        except requests.exceptions.ConnectionError:
            logger.warning("%s 전송 실패: 서버에 연결할 수 없습니다.", label)
            return False

        # 백엔드 응답이 지정한 timeout 안에 오지 않은 경우
        except requests.exceptions.Timeout:
            logger.warning("%s 전송 실패: 요청 시간이 초과되었습니다.", label)
            return False

        # 백엔드가 HTTP 오류 상태 코드를 반환한 경우
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

        # requests 계열의 기타 예외를 분석 서버 밖으로 전파하지 않고 실패로 처리
        except requests.exceptions.RequestException:
            logger.warning("%s 전송 실패: 요청 처리 중 오류가 발생했습니다.", label)
            return False
