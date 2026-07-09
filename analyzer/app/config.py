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
    security_gateway_ip: str
    security_gateway_mac: str
    arp_drop_priority: int
    arp_drop_idle_timeout: int
    arp_drop_hard_timeout: int
    port_scan_window_sec: int
    port_scan_unique_dst_port_threshold: int
    port_scan_syn_count_threshold: int
    port_scan_multi_target_window_sec: int
    port_scan_multi_target_threshold: int
    port_scan_high_unique_dst_port_threshold: int
    port_scan_common_port_hit_threshold: int
    port_scan_alert_cooldown_sec: int
    icmp_pps_threshold: float
    icmp_min_packet_count: int
    icmp_high_pps_threshold: float
    icmp_high_pps_multiplier: float
    icmp_large_payload_threshold: int
    event_dedup_window_sec: int
    rate_limit_priority: int
    rate_limit_idle_timeout: int
    rate_limit_hard_timeout: int
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
        security_gateway_ip=os.getenv("SECURITY_GATEWAY_IP", "10.0.0.254"),
        security_gateway_mac=os.getenv(
            "SECURITY_GATEWAY_MAC",
            "00:00:00:00:ff:ff",
        ),
        arp_drop_priority=get_int_env("ARP_DROP_PRIORITY", 650),
        arp_drop_idle_timeout=get_int_env("ARP_DROP_IDLE_TIMEOUT", 60),
        arp_drop_hard_timeout=get_int_env("ARP_DROP_HARD_TIMEOUT", 300),
        port_scan_window_sec=get_int_env("PORT_SCAN_WINDOW_SEC", 5),
        port_scan_unique_dst_port_threshold=get_int_env(
            "PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD",
            10,
        ),
        port_scan_syn_count_threshold=get_int_env(
            "PORT_SCAN_SYN_COUNT_THRESHOLD",
            10,
        ),
        port_scan_multi_target_window_sec=get_int_env(
            "PORT_SCAN_MULTI_TARGET_WINDOW_SEC",
            30,
        ),
        port_scan_multi_target_threshold=get_int_env(
            "PORT_SCAN_MULTI_TARGET_THRESHOLD",
            2,
        ),
        port_scan_high_unique_dst_port_threshold=get_int_env(
            "PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD",
            25,
        ),
        port_scan_common_port_hit_threshold=get_int_env(
            "PORT_SCAN_COMMON_PORT_HIT_THRESHOLD",
            3,
        ),
        port_scan_alert_cooldown_sec=get_int_env(
            "PORT_SCAN_ALERT_COOLDOWN_SEC",
            30,
        ),
        icmp_pps_threshold=get_float_env("ICMP_PPS_THRESHOLD", 100),
        icmp_min_packet_count=get_int_env("ICMP_MIN_PACKET_COUNT", 100),
        icmp_high_pps_threshold=get_float_env("ICMP_HIGH_PPS_THRESHOLD", 300),
        icmp_high_pps_multiplier=get_float_env("ICMP_HIGH_PPS_MULTIPLIER", 3.0),
        icmp_large_payload_threshold=get_int_env("ICMP_LARGE_PAYLOAD_THRESHOLD", 512),
        event_dedup_window_sec=get_int_env("EVENT_DEDUP_WINDOW_SEC", 60),
        rate_limit_priority=get_int_env("RATE_LIMIT_PRIORITY", 500),
        rate_limit_idle_timeout=get_int_env("RATE_LIMIT_IDLE_TIMEOUT", 60),
        rate_limit_hard_timeout=get_int_env("RATE_LIMIT_HARD_TIMEOUT", 300),
        rate_limit_pps=get_int_env("RATE_LIMIT_PPS", 100),
    )
