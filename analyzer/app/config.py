import os
from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address


@dataclass(frozen=True)
class AnalyzerConfig:
    """분석 서버 실행에 필요한 환경 설정을 한 객체로 묶는다."""

    analyzer_id: str
    interface: str
    window_sec: int
    status_interval_sec: int
    packet_buffer_max_size: int
    backend_base_url: str
    backend_api_key: str
    port_scan_window_sec: int
    port_scan_unique_dst_port_threshold: int
    port_scan_syn_count_threshold: int
    port_scan_multi_target_window_sec: int
    port_scan_horizontal_target_threshold: int
    security_trusted_source_ips: set[str]
    trusted_horizontal_scan_threshold: int
    port_scan_high_unique_dst_port_threshold: int
    port_scan_alert_cooldown_sec: int
    icmp_pps_threshold: float
    icmp_min_packet_count: int
    icmp_high_pps_threshold: float
    icmp_critical_pps_threshold: float
    udp_pps_threshold: float
    udp_min_packet_count: int
    udp_high_pps_threshold: float
    udp_critical_pps_threshold: float
    udp_bps_threshold: float
    udp_high_bps_threshold: float
    udp_critical_bps_threshold: float
    syn_pps_threshold: float
    syn_min_count: int
    syn_high_pps_threshold: float
    syn_critical_pps_threshold: float
    syn_max_unique_ports: int
    event_dedup_window_sec: int
    rate_limit_priority: int
    rate_limit_idle_timeout: int
    rate_limit_hard_timeout: int
    rate_limit_pps: int
    drop_priority: int
    drop_idle_timeout: int
    drop_hard_timeout: int
    security_event_queue_max_size: int
    security_event_send_batch_size: int


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


def get_ip_set_env(name: str) -> set[str]:
    value = os.getenv(name, "")
    addresses = set()
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item:
            continue
        try:
            address = ip_address(item)
        except ValueError as exc:
            raise RuntimeError(f"{name} must contain valid IPv4 addresses") from exc
        if not isinstance(address, IPv4Address):
            raise RuntimeError(f"{name} must contain valid IPv4 addresses")
        addresses.add(str(address))
    return addresses


def load_config() -> AnalyzerConfig:
    config = AnalyzerConfig(
        analyzer_id=os.getenv("ANALYZER_ID", "analyzer-1"),
        interface=os.getenv("ANALYZER_INTERFACE", "eth0"),
        window_sec=get_int_env("ANALYZER_WINDOW_SEC", 1),
        status_interval_sec=get_int_env("ANALYZER_STATUS_INTERVAL_SEC", 5),
        packet_buffer_max_size=get_int_env(
            "ANALYZER_PACKET_BUFFER_MAX_SIZE",
            100_000,
        ),
        backend_base_url=os.getenv("BACKEND_BASE_URL", "http://127.0.0.1:8000"),
        backend_api_key=os.getenv("BACKEND_API_KEY", "").strip(),
        port_scan_window_sec=get_int_env("PORT_SCAN_WINDOW_SEC", 5),
        port_scan_unique_dst_port_threshold=get_int_env(
            "PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD",
            15,
        ),
        port_scan_syn_count_threshold=get_int_env(
            "PORT_SCAN_SYN_COUNT_THRESHOLD",
            30,
        ),
        port_scan_multi_target_window_sec=get_int_env(
            "PORT_SCAN_MULTI_TARGET_WINDOW_SEC",
            30,
        ),
        port_scan_horizontal_target_threshold=get_int_env(
            "PORT_SCAN_HORIZONTAL_TARGET_THRESHOLD",
            3,
        ),
        security_trusted_source_ips=get_ip_set_env("SECURITY_TRUSTED_SOURCE_IPS"),
        trusted_horizontal_scan_threshold=get_int_env(
            "TRUSTED_HORIZONTAL_SCAN_THRESHOLD",
            10,
        ),
        port_scan_high_unique_dst_port_threshold=get_int_env(
            "PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD",
            50,
        ),
        port_scan_alert_cooldown_sec=get_int_env(
            "PORT_SCAN_ALERT_COOLDOWN_SEC",
            60,
        ),
        icmp_pps_threshold=get_float_env("ICMP_PPS_THRESHOLD", 150),
        icmp_min_packet_count=get_int_env("ICMP_MIN_PACKET_COUNT", 100),
        icmp_high_pps_threshold=get_float_env("ICMP_HIGH_PPS_THRESHOLD", 500),
        icmp_critical_pps_threshold=get_float_env(
            "ICMP_CRITICAL_PPS_THRESHOLD",
            1000,
        ),
        udp_pps_threshold=get_float_env("UDP_PPS_THRESHOLD", 250),
        udp_min_packet_count=get_int_env("UDP_MIN_PACKET_COUNT", 100),
        udp_high_pps_threshold=get_float_env("UDP_HIGH_PPS_THRESHOLD", 800),
        udp_critical_pps_threshold=get_float_env(
            "UDP_CRITICAL_PPS_THRESHOLD",
            1500,
        ),
        udp_bps_threshold=get_float_env("UDP_BPS_THRESHOLD", 2_000_000),
        udp_high_bps_threshold=get_float_env("UDP_HIGH_BPS_THRESHOLD", 8_000_000),
        udp_critical_bps_threshold=get_float_env(
            "UDP_CRITICAL_BPS_THRESHOLD",
            15_000_000,
        ),
        syn_pps_threshold=get_float_env("SYN_PPS_THRESHOLD", 120),
        syn_min_count=get_int_env("SYN_MIN_COUNT", 30),
        syn_high_pps_threshold=get_float_env("SYN_HIGH_PPS_THRESHOLD", 400),
        syn_critical_pps_threshold=get_float_env(
            "SYN_CRITICAL_PPS_THRESHOLD",
            800,
        ),
        syn_max_unique_ports=get_int_env("SYN_MAX_UNIQUE_PORTS", 5),
        event_dedup_window_sec=get_int_env("EVENT_DEDUP_WINDOW_SEC", 60),
        rate_limit_priority=get_int_env("RATE_LIMIT_PRIORITY", 500),
        rate_limit_idle_timeout=get_int_env("RATE_LIMIT_IDLE_TIMEOUT", 60),
        rate_limit_hard_timeout=get_int_env("RATE_LIMIT_HARD_TIMEOUT", 300),
        rate_limit_pps=get_int_env("RATE_LIMIT_PPS", 100),
        drop_priority=get_int_env("DROP_PRIORITY", 700),
        drop_idle_timeout=get_int_env("DROP_IDLE_TIMEOUT", 30),
        drop_hard_timeout=get_int_env("DROP_HARD_TIMEOUT", 120),
        security_event_queue_max_size=get_int_env(
            "SECURITY_EVENT_QUEUE_MAX_SIZE",
            500,
        ),
        security_event_send_batch_size=get_int_env(
            "SECURITY_EVENT_SEND_BATCH_SIZE",
            100,
        ),
    )
    validate_config(config)
    return config


def validate_config(config: AnalyzerConfig) -> None:
    """잘못된 환경변수 조합을 실행 시작 시점에 차단한다."""

    _require_text("ANALYZER_ID", config.analyzer_id)
    _require_text("ANALYZER_INTERFACE", config.interface)
    _require_text("BACKEND_BASE_URL", config.backend_base_url)
    _require_max_length("ANALYZER_ID", config.analyzer_id, 30)
    _require_max_length("ANALYZER_INTERFACE", config.interface, 30)
    _require_positive("ANALYZER_WINDOW_SEC", config.window_sec)
    _require_positive("ANALYZER_STATUS_INTERVAL_SEC", config.status_interval_sec)
    _require_positive(
        "ANALYZER_PACKET_BUFFER_MAX_SIZE",
        config.packet_buffer_max_size,
    )

    _require_positive("PORT_SCAN_WINDOW_SEC", config.port_scan_window_sec)
    _require_positive(
        "PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD",
        config.port_scan_unique_dst_port_threshold,
    )
    _require_positive(
        "PORT_SCAN_SYN_COUNT_THRESHOLD",
        config.port_scan_syn_count_threshold,
    )
    _require_positive(
        "PORT_SCAN_MULTI_TARGET_WINDOW_SEC",
        config.port_scan_multi_target_window_sec,
    )
    _require_positive(
        "PORT_SCAN_HORIZONTAL_TARGET_THRESHOLD",
        config.port_scan_horizontal_target_threshold,
    )
    _require_order(
        "PORT_SCAN_HORIZONTAL_TARGET_THRESHOLD",
        config.port_scan_horizontal_target_threshold,
        "TRUSTED_HORIZONTAL_SCAN_THRESHOLD",
        config.trusted_horizontal_scan_threshold,
    )
    _require_order(
        "PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD",
        config.port_scan_unique_dst_port_threshold,
        "PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD",
        config.port_scan_high_unique_dst_port_threshold,
    )
    _require_positive(
        "PORT_SCAN_ALERT_COOLDOWN_SEC",
        config.port_scan_alert_cooldown_sec,
    )

    _require_order3(
        "ICMP_PPS_THRESHOLD",
        config.icmp_pps_threshold,
        "ICMP_HIGH_PPS_THRESHOLD",
        config.icmp_high_pps_threshold,
        "ICMP_CRITICAL_PPS_THRESHOLD",
        config.icmp_critical_pps_threshold,
    )
    _require_positive("ICMP_MIN_PACKET_COUNT", config.icmp_min_packet_count)
    _require_order3(
        "UDP_PPS_THRESHOLD",
        config.udp_pps_threshold,
        "UDP_HIGH_PPS_THRESHOLD",
        config.udp_high_pps_threshold,
        "UDP_CRITICAL_PPS_THRESHOLD",
        config.udp_critical_pps_threshold,
    )
    _require_order3(
        "UDP_BPS_THRESHOLD",
        config.udp_bps_threshold,
        "UDP_HIGH_BPS_THRESHOLD",
        config.udp_high_bps_threshold,
        "UDP_CRITICAL_BPS_THRESHOLD",
        config.udp_critical_bps_threshold,
    )
    _require_positive("UDP_MIN_PACKET_COUNT", config.udp_min_packet_count)
    _require_order3(
        "SYN_PPS_THRESHOLD",
        config.syn_pps_threshold,
        "SYN_HIGH_PPS_THRESHOLD",
        config.syn_high_pps_threshold,
        "SYN_CRITICAL_PPS_THRESHOLD",
        config.syn_critical_pps_threshold,
    )
    _require_positive("SYN_MIN_COUNT", config.syn_min_count)
    _require_positive("SYN_MAX_UNIQUE_PORTS", config.syn_max_unique_ports)

    _require_positive("EVENT_DEDUP_WINDOW_SEC", config.event_dedup_window_sec)
    _require_positive("RATE_LIMIT_PRIORITY", config.rate_limit_priority)
    _require_positive("RATE_LIMIT_IDLE_TIMEOUT", config.rate_limit_idle_timeout)
    _require_positive("RATE_LIMIT_HARD_TIMEOUT", config.rate_limit_hard_timeout)
    _require_positive("RATE_LIMIT_PPS", config.rate_limit_pps)
    _require_order(
        "RATE_LIMIT_IDLE_TIMEOUT",
        config.rate_limit_idle_timeout,
        "RATE_LIMIT_HARD_TIMEOUT",
        config.rate_limit_hard_timeout,
    )
    _require_positive("DROP_PRIORITY", config.drop_priority)
    _require_positive("DROP_IDLE_TIMEOUT", config.drop_idle_timeout)
    _require_positive("DROP_HARD_TIMEOUT", config.drop_hard_timeout)
    _require_order(
        "DROP_IDLE_TIMEOUT",
        config.drop_idle_timeout,
        "DROP_HARD_TIMEOUT",
        config.drop_hard_timeout,
    )
    _require_positive(
        "SECURITY_EVENT_QUEUE_MAX_SIZE",
        config.security_event_queue_max_size,
    )
    _require_order(
        "SECURITY_EVENT_SEND_BATCH_SIZE",
        config.security_event_send_batch_size,
        "SECURITY_EVENT_QUEUE_MAX_SIZE",
        config.security_event_queue_max_size,
    )


def _require_text(name: str, value: str) -> None:
    if not value.strip():
        raise RuntimeError(f"{name} must not be empty")


def _require_max_length(name: str, value: str, max_length: int) -> None:
    if len(value) > max_length:
        raise RuntimeError(f"{name} must be {max_length} characters or less")


def _require_positive(name: str, value: int | float) -> None:
    if value <= 0:
        raise RuntimeError(f"{name} must be greater than 0")


def _require_order(
    low_name: str,
    low_value: int | float,
    high_name: str,
    high_value: int | float,
) -> None:
    _require_positive(low_name, low_value)
    _require_positive(high_name, high_value)
    if low_value > high_value:
        raise RuntimeError(f"{low_name} must be less than or equal to {high_name}")


def _require_order3(
    low_name: str,
    low_value: int | float,
    high_name: str,
    high_value: int | float,
    critical_name: str,
    critical_value: int | float,
) -> None:
    _require_order(low_name, low_value, high_name, high_value)
    _require_order(high_name, high_value, critical_name, critical_value)
