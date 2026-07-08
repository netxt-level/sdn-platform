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

    def get_or_create_from_event(self, event):
        self.events.append(event)
        return {
            "id": f"response-{event['event_id']}",
            "event_id": event["event_id"],
        }

    def list_responses(self, limit):
        return [{"id": "response-1", "limit": limit}]


class StubFlowRepository:
    def __init__(self):
        self.calls = []

    def get_or_create_from_mitigation(self, *, event, security_response_id):
        self.calls.append((event, security_response_id))
        if event.get("mitigation") is None:
            return None
        return {
            "id": f"flow-{event['event_id']}",
            "security_response_id": security_response_id,
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
    service = module.SecurityService(
        security_event_repository=event_repository,
        security_response_repository=response_repository,
        flow_repository=flow_repository,
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
    assert manager.messages == [
        {
            "type": "security_events",
            "data": {
                **payload,
                "security_responses": [
                    {"id": "response-evt-alert", "event_id": "evt-alert"},
                    {
                        "id": "response-evt-rate-limit",
                        "event_id": "evt-rate-limit",
                    },
                ],
                "flow_rules": [
                    {
                        "id": "flow-evt-rate-limit",
                        "security_response_id": "response-evt-rate-limit",
                    }
                ],
            },
        }
    ]
