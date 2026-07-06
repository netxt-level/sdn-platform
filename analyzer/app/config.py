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
    port_scan_window_sec: int
    port_scan_unique_dst_port_threshold: int
    port_scan_syn_count_threshold: int
    port_scan_multi_target_window_sec: int
    port_scan_multi_target_threshold: int
    port_scan_high_unique_dst_port_threshold: int
    port_scan_alert_cooldown_sec: int
    icmp_pps_threshold: float
    icmp_min_packet_count: int
    icmp_high_pps_threshold: float
    icmp_high_pps_multiplier: float
    icmp_baseline_spike_multiplier: float
    icmp_baseline_min_pps: float
    icmp_alert_cooldown_sec: int
    rate_limit_priority: int
    rate_limit_idle_timeout: int
    rate_limit_hard_timeout: int
    rate_limit_pps: int


def get_int_env(name: str, default: int) -> int:
    # 숫자 환경변수는 시작 시점에 검증해 잘못된 설정을 명확한 오류로 드러낸다.
    value = os.getenv(name)

    if value is None:
        return default

    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


def get_float_env(name: str, default: float) -> float:
    # 실수형 기준값도 시작 시점에 검증해 잘못된 탐지 설정을 빨리 드러낸다.
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
        port_scan_window_sec=get_int_env("PORT_SCAN_WINDOW_SEC", 5),
        port_scan_unique_dst_port_threshold=get_int_env(
            "PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD",
            20,
        ),
        port_scan_syn_count_threshold=get_int_env(
            "PORT_SCAN_SYN_COUNT_THRESHOLD",
            20,
        ),
        port_scan_multi_target_window_sec=get_int_env(
            "PORT_SCAN_MULTI_TARGET_WINDOW_SEC",
            30,
        ),
        port_scan_multi_target_threshold=get_int_env(
            "PORT_SCAN_MULTI_TARGET_THRESHOLD",
            3,
        ),
        port_scan_high_unique_dst_port_threshold=get_int_env(
            "PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD",
            50,
        ),
        port_scan_alert_cooldown_sec=get_int_env(
            "PORT_SCAN_ALERT_COOLDOWN_SEC",
            60,
        ),
        icmp_pps_threshold=get_float_env("ICMP_PPS_THRESHOLD", 1000),
        icmp_min_packet_count=get_int_env("ICMP_MIN_PACKET_COUNT", 1000),
        icmp_high_pps_threshold=get_float_env("ICMP_HIGH_PPS_THRESHOLD", 3000),
        icmp_high_pps_multiplier=get_float_env("ICMP_HIGH_PPS_MULTIPLIER", 3.0),
        icmp_baseline_spike_multiplier=get_float_env(
            "ICMP_BASELINE_SPIKE_MULTIPLIER",
            5.0,
        ),
        icmp_baseline_min_pps=get_float_env("ICMP_BASELINE_MIN_PPS", 100),
        icmp_alert_cooldown_sec=get_int_env("ICMP_ALERT_COOLDOWN_SEC", 60),
        rate_limit_priority=get_int_env("RATE_LIMIT_PRIORITY", 500),
        rate_limit_idle_timeout=get_int_env("RATE_LIMIT_IDLE_TIMEOUT", 60),
        rate_limit_hard_timeout=get_int_env("RATE_LIMIT_HARD_TIMEOUT", 300),
        rate_limit_pps=get_int_env("RATE_LIMIT_PPS", 100),
    )
