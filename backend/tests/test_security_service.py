import asyncio


class RecordingManager:
    def __init__(self):
        self.messages = []

    async def broadcast(self, message):
        self.messages.append(message)


class StubSecurityEventRepository:
    def __init__(self):
        self.saved_events = []

    def save_security_events(self, events):
        self.saved_events.append(events)

    def list_security_events(self, limit):
        return [{"event_id": "evt-1", "limit": limit}]


class StubSecurityResponseRepository:
    def __init__(self):
        self.events = []
        self.status_updates = []

    def get_or_create_from_event(self, event):
        self.events.append(event)
        return {
            "id": f"response-{event['event_id']}",
            "event_id": event["event_id"],
            "status": "PENDING",
        }

    def list_responses(self, limit):
        return [{"id": "response-1", "limit": limit}]

    def update_status(self, response_id, **values):
        self.status_updates.append((response_id, values))
        return {
            "id": response_id,
            "event_id": response_id.removeprefix("response-"),
            **values,
        }


class StubFlowRepository:
    def __init__(self):
        self.calls = []
        self.existing_flows = []

    def get_or_create_from_mitigation(self, *, event, security_response_id):
        self.calls.append((event, security_response_id))
        if event.get("mitigation") is None:
            return None
        return {
            "id": f"flow-{event['event_id']}",
            "security_response_id": security_response_id,
            "status": "PENDING",
            "controller_rule_id": None,
            "controller_response": None,
            "error_message": None,
        }

    def list_by_fingerprint(self, fingerprint):
        return list(self.existing_flows)


class StubFlowService:
    def __init__(self):
        self.applied = []
        self.deleted = []

    def apply_flow(self, flow_rule):
        self.applied.append(flow_rule)
        return {
            **flow_rule,
            "status": "APPLIED",
            "controller_rule_id": flow_rule["id"],
            "controller_response": {
                "status": "APPLIED",
                "meter_id": 7,
            },
        }

    def delete_flow(self, flow_rule_id):
        self.deleted.append(flow_rule_id)
        return {"id": flow_rule_id, "status": "REMOVED"}


class FailedFlowService:
    def apply_flow(self, flow_rule):
        return {
            **flow_rule,
            "status": "FAILED",
            "controller_response": {
                "detail": "switch is not connected: s1",
            },
            "error_message": "switch is not connected: s1",
        }


def test_security_service_stores_events_and_broadcasts_response_context(
    load_service_module,
):
    manager = RecordingManager()
    module = load_service_module(
        "security_service",
        stubs={
            "app.core.websocket": {"manager": manager},
            "app.repositories.flow_repository": {"FlowRepository": StubFlowRepository},
            "app.repositories.security_event_repository": {
                "SecurityEventRepository": StubSecurityEventRepository,
            },
            "app.repositories.security_response_repository": {
                "SecurityResponseRepository": StubSecurityResponseRepository,
            },
        },
    )
    event_repository = StubSecurityEventRepository()
    response_repository = StubSecurityResponseRepository()
    flow_repository = StubFlowRepository()
    flow_service = StubFlowService()
    service = module.SecurityService(
        security_event_repository=event_repository,
        security_response_repository=response_repository,
        flow_repository=flow_repository,
        flow_service=flow_service,
    )
    events = [
        {"event_id": "evt-alert", "mitigation": None},
        {"event_id": "evt-rate-limit", "mitigation": {"action": "RATE_LIMIT"}},
    ]
    payload = {"analyzer_id": "analyzer-1", "events": events}

    asyncio.run(service.receive_events(payload))

    assert event_repository.saved_events == [events]
    assert response_repository.events == events
    assert flow_repository.calls == [
        (events[0], "response-evt-alert"),
        (events[1], "response-evt-rate-limit"),
    ]
    assert [item["id"] for item in flow_service.applied] == [
        "flow-evt-rate-limit"
    ]
    assert [
        update[1]["status"]
        for update in response_repository.status_updates
    ] == ["APPLYING", "APPLIED"]
    assert manager.messages == [
        {
            "type": "security_events",
            "data": {
                **payload,
                "security_responses": [
                    {
                        "id": "response-evt-alert",
                        "event_id": "evt-alert",
                        "status": "PENDING",
                    },
                    {
                        "id": "response-evt-rate-limit",
                        "event_id": "evt-rate-limit",
                        "status": "APPLIED",
                        "response_payload": {
                            "flow_rule_id": "flow-evt-rate-limit",
                            "controller_rule_id": "flow-evt-rate-limit",
                            "controller_response": {
                                "status": "APPLIED",
                                "meter_id": 7,
                            },
                        },
                        "decision_reason": (
                            "analyzer mitigation applied automatically"
                        ),
                        "approved_by": "automatic-policy",
                        "approved_at": (
                            response_repository.status_updates[1][1][
                                "approved_at"
                            ]
                        ),
                        "requested_at": (
                            response_repository.status_updates[1][1][
                                "requested_at"
                            ]
                        ),
                        "completed_at": (
                            response_repository.status_updates[1][1][
                                "completed_at"
                            ]
                        ),
                        "error_message": None,
                    },
                ],
                "flow_rules": [
                    {
                        "id": "flow-evt-rate-limit",
                        "security_response_id": "response-evt-rate-limit",
                        "status": "APPLIED",
                        "controller_rule_id": "flow-evt-rate-limit",
                        "controller_response": {
                            "status": "APPLIED",
                            "meter_id": 7,
                        },
                        "error_message": None,
                    }
                ],
            },
        }
    ]


def test_security_service_records_automatic_response_failure(
    load_service_module,
):
    manager = RecordingManager()
    module = load_service_module(
        "security_service",
        stubs={
            "app.core.websocket": {"manager": manager},
            "app.repositories.flow_repository": {"FlowRepository": StubFlowRepository},
            "app.repositories.security_event_repository": {
                "SecurityEventRepository": StubSecurityEventRepository,
            },
            "app.repositories.security_response_repository": {
                "SecurityResponseRepository": StubSecurityResponseRepository,
            },
        },
    )
    response_repository = StubSecurityResponseRepository()
    service = module.SecurityService(
        security_event_repository=StubSecurityEventRepository(),
        security_response_repository=response_repository,
        flow_repository=StubFlowRepository(),
        flow_service=FailedFlowService(),
    )

    asyncio.run(service.receive_events({
        "analyzer_id": "analyzer-1",
        "events": [
            {
                "event_id": "evt-failed",
                "mitigation": {"action": "RATE_LIMIT"},
            },
        ],
    }))

    final_update = response_repository.status_updates[-1][1]
    assert final_update["status"] == "FAILED"
    assert final_update["decision_reason"] == (
        "automatic analyzer mitigation failed"
    )
    assert final_update["error_message"] == "switch is not connected: s1"
    assert manager.messages[0]["data"]["flow_rules"][0]["status"] == "FAILED"


def test_critical_event_without_mitigation_gets_drop_policy(
    load_service_module,
):
    manager = RecordingManager()
    module = load_service_module(
        "security_service",
        stubs={
            "app.core.websocket": {"manager": manager},
            "app.repositories.flow_repository": {"FlowRepository": StubFlowRepository},
            "app.repositories.security_event_repository": {
                "SecurityEventRepository": StubSecurityEventRepository,
            },
            "app.repositories.security_response_repository": {
                "SecurityResponseRepository": StubSecurityResponseRepository,
            },
        },
    )
    event_repository = StubSecurityEventRepository()
    flow_repository = StubFlowRepository()
    flow_service = StubFlowService()
    service = module.SecurityService(
        security_event_repository=event_repository,
        security_response_repository=StubSecurityResponseRepository(),
        flow_repository=flow_repository,
        flow_service=flow_service,
    )
    event = {
        "event_id": "evt-critical",
        "event_fingerprint": "critical-fingerprint",
        "severity": "critical",
        "src_ip": "10.0.0.3",
        "dst_ip": "10.0.0.100",
        "protocol": "ICMP",
        "mitigation": None,
    }
    flow_repository.existing_flows = [
        {
            "id": "old-rate-limit",
            "action": "RATE_LIMIT",
            "status": "APPLIED",
        },
    ]

    asyncio.run(service.receive_events({"events": [event]}))

    stored_event = event_repository.saved_events[0][0]
    assert stored_event["recommended_action"] == "drop"
    assert stored_event["mitigation"]["action"] == "DROP"
    assert stored_event["mitigation"]["priority"] == 600
    assert len(flow_service.applied) == 1
    assert flow_service.deleted == ["old-rate-limit"]
