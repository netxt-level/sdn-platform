import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AnalyzerConfig:
    """분석 서버 실행에 필요한 환경 설정을 한 객체로 묶는다."""

    analyzer_id: str
    interface: str
    window_sec: int
    status_interval_sec: int
    backend_base_url: str
    security_gateway_ip: str
    security_gateway_mac: str
    security_event_cooldown_sec: int


def get_int_env(name: str, default: int) -> int:
    # 숫자 환경변수는 시작 시점에 검증해 잘못된 설정을 명확한 오류로 드러낸다.
    value = os.getenv(name)

    if value is None:
        return default

    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


def load_config() -> AnalyzerConfig:
    return AnalyzerConfig(
        analyzer_id=os.getenv("ANALYZER_ID", "analyzer-1"),
        interface=os.getenv("ANALYZER_INTERFACE", "en0"),
        window_sec=get_int_env("ANALYZER_WINDOW_SEC", 1),
        status_interval_sec=get_int_env("ANALYZER_STATUS_INTERVAL_SEC", 5),
        backend_base_url=os.getenv("BACKEND_BASE_URL", "http://127.0.0.1:8000"),
        security_gateway_ip=os.getenv("SECURITY_GATEWAY_IP", "10.0.0.254"),
        security_gateway_mac=os.getenv("SECURITY_GATEWAY_MAC", "00:00:00:00:ff:ff"),
        security_event_cooldown_sec=get_int_env("SECURITY_EVENT_COOLDOWN_SEC", 30),
    )
