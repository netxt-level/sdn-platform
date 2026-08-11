from datetime import datetime


class StubFlowRepository:
    def __init__(self):
        self.status_updates = []
        self.flows = []
        self.deleted_ids = []

    def create_manual_flow(self, **values):
        return {
            "id": "rule-1",
            "status": "PENDING",
            **values,
        }

    def update_status(self, flow_rule_id, **values):
        self.status_updates.append((flow_rule_id, values))
        return {
            "id": flow_rule_id,
            "switch_id": "s1",
            "match": {"ipv4_src": "10.0.0.2"},
            "action": "DROP",
            "priority": 500,
            "idle_timeout": None,
            "hard_timeout": None,
            **values,
        }

    def list_flows(self, src_ip=None):
        return list(self.flows)

    def get_flow(self, flow_rule_id):
        return {
            "id": flow_rule_id,
            "switch_id": "s1",
            "match": {"ipv4_src": "10.0.0.2"},
            "action": "DROP",
            "priority": 500,
            "status": "APPLIED",
            "controller_rule_id": flow_rule_id,
            "controller_response": {"status": "APPLIED"},
            "applied_at": datetime.now(),
        }

    def delete_flow(self, flow_rule_id):
        self.deleted_ids.append(flow_rule_id)
        deleted = self.get_flow(flow_rule_id)
        self.flows = [
            flow for flow in self.flows if flow["id"] != flow_rule_id
        ]
        return deleted


class SuccessfulControllerClient:
    def __init__(self):
        self.rules = []

    def install_flow_rule(self, rule):
        self.rules.append(rule)
        return {
            "controller_rule_id": rule["id"],
            "status": "APPLIED",
            "cookie": "0x5344e20000000001",
        }

    def delete_flow_rule(self, rule):
        self.rules.append(rule)
        return {
            "controller_rule_id": rule["id"],
            "switch_id": "s1",
            "status": "REMOVED",
        }

    def get_topology(self):
        return {
            "switches": [
                {"switch_id": "s1", "state": "connected"},
                {"switch_id": "s2", "state": "disconnected"},
            ],
            "links": [
                {
                    "source": "s1",
                    "destination": "s2",
                    "state": "active",
                },
            ],
            "hosts": [
                {
                    "name": "h1",
                    "mac": "00:00:00:00:00:01",
                    "ipv4": "10.0.0.1",
                    "switch_id": "s1",
                    "port": 1,
                },
                {
                    "name": "web",
                    "mac": "00:00:00:00:01:00",
                    "ipv4": "10.0.0.100",
                    "switch_id": "s4",
                    "port": 3,
                },
            ],
        }

    def get_stats(self):
        return {
            "updated_at": "2026-07-21T00:00:00+00:00",
            "switches": [],
        }


def flow_data():
    return {
        "switch_id": "s1",
        "match": {"ipv4_src": "10.0.0.2"},
        "action": "DROP",
        "priority": 500,
    }


def test_create_flow_persists_applying_and_applied_lifecycle(
    load_service_module,
):
    class StubControllerClientError(RuntimeError):
        pass

    module = load_service_module(
        "flow_service",
        stubs={
            "app.clients.controller": {
                "ControllerClient": SuccessfulControllerClient,
                "ControllerClientError": StubControllerClientError,
            },
            "app.repositories.flow_repository": {
                "FlowRepository": StubFlowRepository,
            },
        },
    )
    repository = StubFlowRepository()
    controller = SuccessfulControllerClient()
    service = module.FlowService(repository, controller)

    result = service.create_flow(flow_data())

    assert result["status"] == "APPLIED"
    assert result["controller_rule_id"] == "rule-1"
    assert len(controller.rules) == 1
    assert [update[1]["status"] for update in repository.status_updates] == [
        "APPLYING",
        "APPLIED",
    ]
    assert isinstance(
        repository.status_updates[0][1]["requested_at"],
        datetime,
    )
    assert isinstance(result["applied_at"], datetime)


def test_controller_failure_is_stored_as_failed(load_service_module):
    class StubControllerClientError(RuntimeError):
        def __init__(self, message, response=None):
            super().__init__(message)
            self.response = response

    class FailingControllerClient:
        def install_flow_rule(self, rule):
            raise StubControllerClientError(
                "switch is not connected",
                {"detail": "switch is not connected"},
            )

    module = load_service_module(
        "flow_service",
        stubs={
            "app.clients.controller": {
                "ControllerClient": FailingControllerClient,
                "ControllerClientError": StubControllerClientError,
            },
            "app.repositories.flow_repository": {
                "FlowRepository": StubFlowRepository,
            },
        },
    )
    repository = StubFlowRepository()
    service = module.FlowService(repository, FailingControllerClient())

    result = service.create_flow(flow_data())

    assert result["status"] == "FAILED"
    assert result["error_message"] == "switch is not connected"
    assert result["controller_response"] == {
        "detail": "switch is not connected"
    }
    assert [update[1]["status"] for update in repository.status_updates] == [
        "APPLYING",
        "FAILED",
    ]


def test_get_flows_combines_db_rules_with_live_controller_counters(
    load_service_module,
):
    class StubControllerClientError(RuntimeError):
        pass

    class StatsControllerClient(SuccessfulControllerClient):
        def get_stats(self):
            return {
                "updated_at": "2026-07-21T00:00:00+00:00",
                "switches": [
                    {
                        "switch_id": "s1",
                        "flows": [
                            {
                                "cookie": "0x5344e20000000001",
                                "packet_count": 31,
                                "byte_count": 3100,
                            },
                            {
                                "cookie": "0x5344e20000000001",
                                "packet_count": 30,
                                "byte_count": 3000,
                            },
                        ],
                    },
                ],
            }

    module = load_service_module(
        "flow_service",
        stubs={
            "app.clients.controller": {
                "ControllerClient": StatsControllerClient,
                "ControllerClientError": StubControllerClientError,
            },
            "app.repositories.flow_repository": {
                "FlowRepository": StubFlowRepository,
            },
        },
    )
    repository = StubFlowRepository()
    repository.flows = [{
        **repository.get_flow("rule-1"),
        "controller_response": {"cookie": "0x5344e20000000001"},
    }]

    result = module.FlowService(
        repository,
        StatsControllerClient(),
    ).get_flows()

    assert result["total"] == 1
    assert result["items"][0]["packet_count"] == 31
    assert result["items"][0]["byte_count"] == 3100
    assert result["controller"] == {
        "available": True,
        "updated_at": "2026-07-21T00:00:00+00:00",
        "switches": [
            {"switch_id": "s1", "state": "connected"},
            {"switch_id": "s2", "state": "disconnected"},
        ],
        "links": [
            {
                "source": "s1",
                "destination": "s2",
                "state": "active",
            },
        ],
        "hosts": [
            {
                "name": "h1",
                "mac": "00:00:00:00:00:01",
                "ipv4": "10.0.0.1",
                "switch_id": "s1",
                "port": 1,
            },
            {
                "name": "web",
                "mac": "00:00:00:00:01:00",
                "ipv4": "10.0.0.100",
                "switch_id": "s4",
                "port": 3,
            },
        ],
        "error": None,
    }


def test_get_flows_keeps_db_history_when_controller_is_unavailable(
    load_service_module,
):
    class StubControllerClientError(RuntimeError):
        pass

    class UnavailableControllerClient:
        def get_topology(self):
            raise StubControllerClientError("controller unavailable")

    module = load_service_module(
        "flow_service",
        stubs={
            "app.clients.controller": {
                "ControllerClient": UnavailableControllerClient,
                "ControllerClientError": StubControllerClientError,
            },
            "app.repositories.flow_repository": {
                "FlowRepository": StubFlowRepository,
            },
        },
    )
    repository = StubFlowRepository()
    repository.flows = [repository.get_flow("rule-1")]

    result = module.FlowService(
        repository,
        UnavailableControllerClient(),
    ).get_flows()

    assert result["items"] == repository.flows
    assert result["total"] == 1
    assert result["controller"]["available"] is False
    assert result["controller"]["error"] == "controller unavailable"


def test_get_flows_only_returns_applied_rules(load_service_module):
    class StubControllerClientError(RuntimeError):
        pass

    module = load_service_module(
        "flow_service",
        stubs={
            "app.clients.controller": {
                "ControllerClient": SuccessfulControllerClient,
                "ControllerClientError": StubControllerClientError,
            },
            "app.repositories.flow_repository": {
                "FlowRepository": StubFlowRepository,
            },
        },
    )
    repository = StubFlowRepository()
    repository.flows = [
        {**repository.get_flow("applied-rule"), "status": "APPLIED"},
        {**repository.get_flow("pending-rule"), "status": "PENDING"},
        {**repository.get_flow("failed-rule"), "status": "FAILED"},
        {**repository.get_flow("removed-rule"), "status": "REMOVED"},
        {**repository.get_flow("expired-rule"), "status": "EXPIRED"},
    ]

    result = module.FlowService(
        repository,
        SuccessfulControllerClient(),
    ).get_flows()

    assert [item["id"] for item in result["items"]] == ["applied-rule"]
    assert result["total"] == 1


def test_delete_flow_removes_controller_rule_then_deletes_db_record(
    load_service_module,
):
    class StubControllerClientError(RuntimeError):
        pass

    module = load_service_module(
        "flow_service",
        stubs={
            "app.clients.controller": {
                "ControllerClient": SuccessfulControllerClient,
                "ControllerClientError": StubControllerClientError,
            },
            "app.repositories.flow_repository": {
                "FlowRepository": StubFlowRepository,
            },
        },
    )
    repository = StubFlowRepository()
    controller = SuccessfulControllerClient()
    service = module.FlowService(repository, controller)

    result = service.delete_flow("rule-1")

    assert result["status"] == "REMOVED"
    assert [update[1]["status"] for update in repository.status_updates] == [
        "REMOVING",
    ]
    assert repository.deleted_ids == ["rule-1"]
    assert isinstance(result["removed_at"], datetime)
    assert controller.rules[0]["status"] == "REMOVING"


def test_delete_failure_is_stored_and_can_be_retried(
    load_service_module,
):
    class StubControllerClientError(RuntimeError):
        def __init__(self, message, response=None):
            super().__init__(message)
            self.response = response

    class FailingDeleteControllerClient:
        def delete_flow_rule(self, rule):
            raise StubControllerClientError(
                "Barrier Reply timed out",
                {"status": "FAILED", "error": "Barrier Reply timed out"},
            )

    module = load_service_module(
        "flow_service",
        stubs={
            "app.clients.controller": {
                "ControllerClient": FailingDeleteControllerClient,
                "ControllerClientError": StubControllerClientError,
            },
            "app.repositories.flow_repository": {
                "FlowRepository": StubFlowRepository,
            },
        },
    )
    repository = StubFlowRepository()
    service = module.FlowService(
        repository,
        FailingDeleteControllerClient(),
    )

    result = service.delete_flow("rule-1")

    assert result["status"] == "REMOVE_FAILED"
    assert result["error_message"] == "Barrier Reply timed out"
    assert [update[1]["status"] for update in repository.status_updates] == [
        "REMOVING",
        "REMOVE_FAILED",
    ]
    assert repository.deleted_ids == []


def test_reconcile_updates_expired_and_reapplies_missing_rules(
    load_service_module,
):
    class StubControllerClientError(RuntimeError):
        pass

    class ReconcileControllerClient(SuccessfulControllerClient):
        def list_flow_rules(self):
            return [
                {"controller_rule_id": "expired-rule", "status": "EXPIRED"},
            ]

    module = load_service_module(
        "flow_service",
        stubs={
            "app.clients.controller": {
                "ControllerClient": ReconcileControllerClient,
                "ControllerClientError": StubControllerClientError,
            },
            "app.repositories.flow_repository": {
                "FlowRepository": StubFlowRepository,
            },
        },
    )
    repository = StubFlowRepository()
    repository.flows = [
        {
            **repository.get_flow("expired-rule"),
            "status": "APPLIED",
        },
        {
            **repository.get_flow("missing-rule"),
            "status": "APPLIED",
        },
    ]
    controller = ReconcileControllerClient()
    service = module.FlowService(repository, controller)

    result = service.reconcile_flows()

    assert result == {
        "status": "COMPLETED",
        "checked": 2,
        "updated": 1,
        "reapplied": 1,
        "failures": [],
    }
    assert repository.status_updates[0][1]["status"] == "EXPIRED"
    assert [rule["id"] for rule in controller.rules] == ["missing-rule"]


def test_reconcile_retries_failed_installation(load_service_module):
    class StubControllerClientError(RuntimeError):
        pass

    class EmptyControllerClient(SuccessfulControllerClient):
        def list_flow_rules(self):
            return []

    module = load_service_module(
        "flow_service",
        stubs={
            "app.clients.controller": {
                "ControllerClient": EmptyControllerClient,
                "ControllerClientError": StubControllerClientError,
            },
            "app.repositories.flow_repository": {
                "FlowRepository": StubFlowRepository,
            },
        },
    )
    repository = StubFlowRepository()
    repository.flows = [
        {
            **repository.get_flow("failed-rule"),
            "status": "FAILED",
        },
    ]
    controller = EmptyControllerClient()
    service = module.FlowService(repository, controller)

    result = service.reconcile_flows()

    assert result["status"] == "COMPLETED"
    assert result["reapplied"] == 1
    assert [rule["id"] for rule in controller.rules] == ["failed-rule"]
