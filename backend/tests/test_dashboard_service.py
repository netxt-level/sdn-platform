class StubTrafficRepository:
    def __init__(self):
        self.traffic_calls = []
        self.protocol_calls = []

    def list_traffic_series(self, range_value, bucket_value):
        self.traffic_calls.append((range_value, bucket_value))
        return [
            {
                "timestamp": "2026-07-07T00:00:00+00:00",
                "total_packets": 5,
                "total_bits": 800,
                "pps": 1.0,
                "bps": 160.0,
            }
        ]

    def list_protocol_stats(self, range_value):
        self.protocol_calls.append(range_value)
        return [{"protocol": "TCP", "packet_count": 5, "percentage": 100.0}]


class StubSecurityEventRepository:
    def list_suspicious_hosts(self):
        return [{"ip": "10.0.0.2", "attack_type": "PORT_SCAN"}]


def test_dashboard_service_delegates_history_queries(load_service_module):
    module = load_service_module(
        "dashboard_service",
        stubs={
            "app.repositories.traffic_repository": {
                "TrafficRepository": StubTrafficRepository,
            },
            "app.repositories.security_event_repository": {
                "SecurityEventRepository": StubSecurityEventRepository,
            },
        },
    )
    traffic_repository = StubTrafficRepository()
    security_repository = StubSecurityEventRepository()
    service = module.DashboardService(
        traffic_repository=traffic_repository,
        security_event_repository=security_repository,
    )

    assert service.get_traffic("5m", "5s") == {
        "range": "5m",
        "bucket": "5s",
        "items": [
            {
                "timestamp": "2026-07-07T00:00:00+00:00",
                "total_packets": 5,
                "total_bits": 800,
                "pps": 1.0,
                "bps": 160.0,
            }
        ],
    }
    assert service.get_protocols("1m") == {
        "range": "1m",
        "items": [{"protocol": "TCP", "packet_count": 5, "percentage": 100.0}],
    }
    assert service.get_suspicious_hosts("1w") == {
        "range": "1w",
        "count": 1,
        "items": [{"ip": "10.0.0.2", "attack_type": "PORT_SCAN"}],
    }
    assert traffic_repository.traffic_calls == [("5m", "5s")]
    assert traffic_repository.protocol_calls == ["1m"]


def test_dashboard_summary_has_expected_metric_shape(load_service_module):
    module = load_service_module(
        "dashboard_service",
        stubs={
            "app.repositories.traffic_repository": {
                "TrafficRepository": StubTrafficRepository,
            },
            "app.repositories.security_event_repository": {
                "SecurityEventRepository": StubSecurityEventRepository,
            },
        },
    )
    service = module.DashboardService(
        traffic_repository=StubTrafficRepository(),
        security_event_repository=StubSecurityEventRepository(),
    )

    summary = service.get_summary()

    assert summary == {
        "total_packets": 5,
        "total_bytes": 100,
        "current_pps": 1.0,
        "current_bps": 160.0,
        "network_status": "normal",
    }


def test_dashboard_warning_starts_at_1500_pps(load_service_module):
    module = load_service_module(
        "dashboard_service",
        stubs={
            "app.repositories.traffic_repository": {
                "TrafficRepository": StubTrafficRepository,
            },
            "app.repositories.security_event_repository": {
                "SecurityEventRepository": StubSecurityEventRepository,
            },
        },
    )
    service = module.DashboardService(
        traffic_repository=StubTrafficRepository(),
        security_event_repository=StubSecurityEventRepository(),
    )

    assert service._decide_network_status(
        current_bps=0,
        current_pps=1499,
    ) == "normal"
    assert service._decide_network_status(
        current_bps=0,
        current_pps=1500,
    ) == "warning"


def test_dashboard_bps_thresholds_start_at_10_and_20_mbps(load_service_module):
    module = load_service_module(
        "dashboard_service",
        stubs={
            "app.repositories.traffic_repository": {
                "TrafficRepository": StubTrafficRepository,
            },
            "app.repositories.security_event_repository": {
                "SecurityEventRepository": StubSecurityEventRepository,
            },
        },
    )
    service = module.DashboardService(
        traffic_repository=StubTrafficRepository(),
        security_event_repository=StubSecurityEventRepository(),
    )

    assert service._decide_network_status(
        current_bps=9_999_999,
        current_pps=0,
    ) == "normal"
    assert service._decide_network_status(
        current_bps=10_000_000,
        current_pps=0,
    ) == "warning"
    assert service._decide_network_status(
        current_bps=20_000_000,
        current_pps=0,
    ) == "critical"
