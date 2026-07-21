from datetime import datetime


class StubFlowRepository:
    def __init__(self):
        self.status_updates = []
        self.flows = []

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


def test_delete_flow_persists_removing_and_removed_lifecycle(
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
        "REMOVED",
    ]
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
