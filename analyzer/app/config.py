import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AnalyzerConfig:
    """분석 서버 실행에 필요한 환경 설정을 한곳에 모은다."""

    analyzer_id: str
    interface: str
    window_sec: int
    status_interval_sec: int
    backend_base_url: str
    security_window_sec: int
    security_gateway_ip: str
    security_gateway_mac: str
    security_event_cooldown_sec: int
    port_scan_window_sec: int
    port_scan_unique_dst_port_threshold: int
    port_scan_syn_count_threshold: int
    port_scan_multi_target_window_sec: int
    port_scan_multi_target_threshold: int
    port_scan_high_unique_dst_port_threshold: int
    port_scan_alert_cooldown_sec: int
    icmp_pps_threshold: float
    rate_limit_pps: int


def get_int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default

    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


def get_float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default

    try:
        return float(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a number") from exc


def load_config() -> AnalyzerConfig:
    return AnalyzerConfig(
        analyzer_id=os.getenv("ANALYZER_ID", "analyzer-1"),
        interface=os.getenv("ANALYZER_INTERFACE", "en0"),
        window_sec=get_int_env("ANALYZER_WINDOW_SEC", 1),
        status_interval_sec=get_int_env("ANALYZER_STATUS_INTERVAL_SEC", 5),
        backend_base_url=os.getenv("BACKEND_BASE_URL", "http://127.0.0.1:8000"),
        security_window_sec=get_int_env("SECURITY_WINDOW_SEC", 10),
        security_gateway_ip=os.getenv("SECURITY_GATEWAY_IP", "10.0.0.254"),
        security_gateway_mac=os.getenv("SECURITY_GATEWAY_MAC", "00:00:00:00:ff:ff"),
        security_event_cooldown_sec=get_int_env("SECURITY_EVENT_COOLDOWN_SEC", 30),
        port_scan_window_sec=get_int_env("PORT_SCAN_WINDOW_SEC", 5),
        port_scan_unique_dst_port_threshold=get_int_env(
            "PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD",
            20,
        ),
        port_scan_syn_count_threshold=get_int_env("PORT_SCAN_SYN_COUNT_THRESHOLD", 20),
        port_scan_multi_target_window_sec=get_int_env(
            "PORT_SCAN_MULTI_TARGET_WINDOW_SEC",
            30,
        ),
        port_scan_multi_target_threshold=get_int_env("PORT_SCAN_MULTI_TARGET_THRESHOLD", 3),
        port_scan_high_unique_dst_port_threshold=get_int_env(
            "PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD",
            50,
        ),
        port_scan_alert_cooldown_sec=get_int_env("PORT_SCAN_ALERT_COOLDOWN_SEC", 60),
        icmp_pps_threshold=get_float_env("ICMP_PPS_THRESHOLD", 100),
        rate_limit_pps=get_int_env("SECURITY_RATE_LIMIT_PPS", 50),
    )
