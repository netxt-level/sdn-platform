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
    def __init__(self):
        self.suspicious_host_calls = []

    def list_suspicious_hosts(self, *, range_value=None):
        self.suspicious_host_calls.append(range_value)
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
    assert security_repository.suspicious_host_calls == ["1w"]


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
