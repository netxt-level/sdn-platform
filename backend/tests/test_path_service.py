from datetime import datetime, timedelta, timezone


class StubDashboardService:
    def __init__(self, network_status="normal"):
        self.network_status = network_status

    def get_summary(self):
        return {
            "current_bps": 1000,
            "network_status": self.network_status,
        }


class StubFlowRepository:
    def __init__(self, flow_rules=None):
        self.flow_rules = flow_rules or []
        self.requested_limit = None

    def list_flows(self, *, limit=100):
        self.requested_limit = limit
        return self.flow_rules


def _load_path_service(load_service_module):
    return load_service_module(
        "path_service",
        stubs={
            "app.repositories.flow_repository": {
                "FlowRepository": StubFlowRepository
            },
            "app.services.dashboard_service": {
                "DashboardService": StubDashboardService
            },
        },
    )


def test_stale_pending_rule_does_not_change_active_path(load_service_module):
    module = _load_path_service(load_service_module)
    now = datetime.now(timezone.utc)
    flow_repository = StubFlowRepository([
        {
            "id": "flow-1",
            "status": "PENDING",
            "action": "DROP",
            "created_at": now - timedelta(minutes=11),
            "match": {"ipv4_src": "10.0.0.2"},
        }
    ])
    service = module.PathService(
        dashboard_service=StubDashboardService(),
        flow_repository=flow_repository,
    )

    status = service.get_status()

    assert status["active_path"] == "primary"
    assert flow_repository.requested_limit == 100


def test_recent_pending_rule_changes_active_path(load_service_module):
    module = _load_path_service(load_service_module)
    now = datetime.now(timezone.utc)
    service = module.PathService(
        dashboard_service=StubDashboardService(),
        flow_repository=StubFlowRepository([
            {
                "id": "flow-1",
                "status": "PENDING",
                "action": "RATE_LIMIT",
                "created_at": now - timedelta(minutes=1),
                "match": {"ipv4_src": "10.0.0.2"},
            }
        ]),
    )

    status = service.get_status()

    assert status["active_path"] == "backup"
