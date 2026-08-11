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
    backend_api_key: str
    outbox_path: str
    outbox_delivery_poll_sec: float
    outbox_delivery_batch_size: int
    outbox_retry_base_sec: float
    outbox_retry_max_sec: float
    port_scan_window_sec: int
    port_scan_unique_dst_port_threshold: int
    port_scan_syn_count_threshold: int
    port_scan_multi_target_window_sec: int
    port_scan_multi_target_threshold: int
    port_scan_high_unique_dst_port_threshold: int
    port_scan_alert_cooldown_sec: int
    protected_server_ips: tuple[str, ...]
    server_egress_allowlist: tuple[str, ...]
    server_behavior_alert_cooldown_sec: int
    lateral_fanout_window_sec: int
    lateral_fanout_unique_dst_threshold: int
    lateral_fanout_connection_threshold: int
    exfil_volume_window_sec: int
    exfil_outbound_bps_threshold: float
    exfil_baseline_multiplier: float
    exfil_sustained_windows: int
    c2_beacon_window_sec: int
    c2_beacon_min_connections: int
    c2_beacon_min_interval_sec: float
    c2_beacon_max_interval_sec: float
    c2_beacon_max_jitter_ratio: float
    icmp_pps_threshold: float
    icmp_min_packet_count: int
    icmp_high_pps_threshold: float
    icmp_high_pps_multiplier: float
    icmp_baseline_spike_multiplier: float
    icmp_baseline_min_pps: float
    icmp_alert_cooldown_sec: int
    event_dedup_window_sec: int
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


def get_csv_env(name: str, default: str) -> tuple[str, ...]:
    value = os.getenv(name, default)
    return tuple(
        item.strip()
        for item in value.split(",")
        if item.strip()
    )


def load_config() -> AnalyzerConfig:
    config = AnalyzerConfig(
        analyzer_id=os.getenv("ANALYZER_ID", "analyzer-1"),
        interface=os.getenv("ANALYZER_INTERFACE", "en0"),
        window_sec=get_int_env("ANALYZER_WINDOW_SEC", 1),
        status_interval_sec=get_int_env("ANALYZER_STATUS_INTERVAL_SEC", 5),
        backend_base_url=os.getenv("BACKEND_BASE_URL", "http://127.0.0.1:8000"),
        backend_api_key=os.getenv("ANALYZER_API_KEY", ""),
        outbox_path=os.getenv(
            "ANALYZER_OUTBOX_PATH",
            "/var/lib/sdn-analyzer/outbox.db",
        ),
        outbox_delivery_poll_sec=get_float_env(
            "ANALYZER_OUTBOX_DELIVERY_POLL_SEC",
            1.0,
        ),
        outbox_delivery_batch_size=get_int_env(
            "ANALYZER_OUTBOX_DELIVERY_BATCH_SIZE",
            100,
        ),
        outbox_retry_base_sec=get_float_env(
            "ANALYZER_OUTBOX_RETRY_BASE_SEC",
            1.0,
        ),
        outbox_retry_max_sec=get_float_env(
            "ANALYZER_OUTBOX_RETRY_MAX_SEC",
            60.0,
        ),
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
        protected_server_ips=get_csv_env(
            "PROTECTED_SERVER_IPS",
            "10.0.0.100",
        ),
        server_egress_allowlist=get_csv_env(
            "SERVER_EGRESS_ALLOWLIST",
            "",
        ),
        server_behavior_alert_cooldown_sec=get_int_env(
            "SERVER_BEHAVIOR_ALERT_COOLDOWN_SEC",
            60,
        ),
        lateral_fanout_window_sec=get_int_env(
            "LATERAL_FANOUT_WINDOW_SEC",
            30,
        ),
        lateral_fanout_unique_dst_threshold=get_int_env(
            "LATERAL_FANOUT_UNIQUE_DST_THRESHOLD",
            2,
        ),
        lateral_fanout_connection_threshold=get_int_env(
            "LATERAL_FANOUT_CONNECTION_THRESHOLD",
            3,
        ),
        exfil_volume_window_sec=get_int_env(
            "EXFIL_VOLUME_WINDOW_SEC",
            10,
        ),
        exfil_outbound_bps_threshold=get_float_env(
            "EXFIL_OUTBOUND_BPS_THRESHOLD",
            1_000_000,
        ),
        exfil_baseline_multiplier=get_float_env(
            "EXFIL_BASELINE_MULTIPLIER",
            3.0,
        ),
        exfil_sustained_windows=get_int_env(
            "EXFIL_SUSTAINED_WINDOWS",
            3,
        ),
        c2_beacon_window_sec=get_int_env(
            "C2_BEACON_WINDOW_SEC",
            300,
        ),
        c2_beacon_min_connections=get_int_env(
            "C2_BEACON_MIN_CONNECTIONS",
            6,
        ),
        c2_beacon_min_interval_sec=get_float_env(
            "C2_BEACON_MIN_INTERVAL_SEC",
            20.0,
        ),
        c2_beacon_max_interval_sec=get_float_env(
            "C2_BEACON_MAX_INTERVAL_SEC",
            90.0,
        ),
        c2_beacon_max_jitter_ratio=get_float_env(
            "C2_BEACON_MAX_JITTER_RATIO",
            0.2,
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
        event_dedup_window_sec=get_int_env("EVENT_DEDUP_WINDOW_SEC", 60),
        rate_limit_priority=get_int_env("RATE_LIMIT_PRIORITY", 500),
        rate_limit_idle_timeout=get_int_env("RATE_LIMIT_IDLE_TIMEOUT", 60),
        rate_limit_hard_timeout=get_int_env("RATE_LIMIT_HARD_TIMEOUT", 300),
        rate_limit_pps=get_int_env("RATE_LIMIT_PPS", 100),
    )
    if config.outbox_delivery_poll_sec <= 0:
        raise RuntimeError("ANALYZER_OUTBOX_DELIVERY_POLL_SEC must be positive")
    if config.outbox_delivery_batch_size <= 0:
        raise RuntimeError("ANALYZER_OUTBOX_DELIVERY_BATCH_SIZE must be positive")
    if config.outbox_retry_base_sec <= 0:
        raise RuntimeError("ANALYZER_OUTBOX_RETRY_BASE_SEC must be positive")
    if config.outbox_retry_max_sec < config.outbox_retry_base_sec:
        raise RuntimeError(
            "ANALYZER_OUTBOX_RETRY_MAX_SEC must be at least the retry base"
        )
    if not config.protected_server_ips:
        raise RuntimeError("PROTECTED_SERVER_IPS must contain at least one IP")
    positive_values = {
        "SERVER_BEHAVIOR_ALERT_COOLDOWN_SEC": (
            config.server_behavior_alert_cooldown_sec
        ),
        "LATERAL_FANOUT_WINDOW_SEC": config.lateral_fanout_window_sec,
        "LATERAL_FANOUT_UNIQUE_DST_THRESHOLD": (
            config.lateral_fanout_unique_dst_threshold
        ),
        "LATERAL_FANOUT_CONNECTION_THRESHOLD": (
            config.lateral_fanout_connection_threshold
        ),
        "EXFIL_VOLUME_WINDOW_SEC": config.exfil_volume_window_sec,
        "EXFIL_OUTBOUND_BPS_THRESHOLD": (
            config.exfil_outbound_bps_threshold
        ),
        "EXFIL_BASELINE_MULTIPLIER": config.exfil_baseline_multiplier,
        "EXFIL_SUSTAINED_WINDOWS": config.exfil_sustained_windows,
        "C2_BEACON_WINDOW_SEC": config.c2_beacon_window_sec,
        "C2_BEACON_MIN_CONNECTIONS": config.c2_beacon_min_connections,
        "C2_BEACON_MIN_INTERVAL_SEC": config.c2_beacon_min_interval_sec,
        "C2_BEACON_MAX_INTERVAL_SEC": config.c2_beacon_max_interval_sec,
    }
    for name, value in positive_values.items():
        if value <= 0:
            raise RuntimeError(f"{name} must be positive")
    if (
        config.c2_beacon_min_interval_sec
        >= config.c2_beacon_max_interval_sec
    ):
        raise RuntimeError(
            "C2_BEACON_MIN_INTERVAL_SEC must be below "
            "C2_BEACON_MAX_INTERVAL_SEC"
        )
    if not 0 <= config.c2_beacon_max_jitter_ratio <= 1:
        raise RuntimeError(
            "C2_BEACON_MAX_JITTER_RATIO must be between 0 and 1"
        )
    return config
