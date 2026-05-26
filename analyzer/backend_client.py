import requests


class BackendClient:
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
    
    def send_analyzer_status(self, analyzer_status: dict) -> bool:
        return self._post(
            path="/api/analyzer/status",
            payload=analyzer_status,
            label="analyzer status",
        )

    def _post(self, path: str, payload: dict, label: str) -> bool:
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
            print(f"[Backend] {label} 전송 실패: 서버에 연결할 수 없습니다.")
            return False

        except requests.exceptions.Timeout:
            print(f"[Backend] {label} 전송 실패: 요청 시간이 초과되었습니다.")
            return False

        except requests.exceptions.HTTPError as exc:
            status_code = exc.response.status_code if exc.response else "unknown"
            print(f"[Backend] {label} 전송 실패: HTTP {status_code} 응답을 받았습니다.")
            return False

        except requests.exceptions.RequestException:
            print(f"[Backend] {label} 전송 실패: 요청 처리 중 오류가 발생했습니다.")
            return False
