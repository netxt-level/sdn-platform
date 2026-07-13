import asyncio
import sys
import types


fastapi_stub = types.ModuleType("fastapi")
fastapi_stub.WebSocket = object

encoders_stub = types.ModuleType("fastapi.encoders")
encoders_stub.jsonable_encoder = lambda value: value

sys.modules.setdefault("fastapi", fastapi_stub)
sys.modules.setdefault("fastapi.encoders", encoders_stub)

from app.core.websocket import WebSocketManager  # noqa: E402


class StubWebSocket:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.messages = []

    async def send_json(self, message):
        if self.fail:
            raise RuntimeError("connection closed")
        self.messages.append(message)


def test_broadcast_sends_to_available_clients_and_removes_failed_clients():
    manager = WebSocketManager()
    live_client = StubWebSocket()
    failed_client = StubWebSocket(fail=True)
    manager.active_connections = [live_client, failed_client]

    asyncio.run(manager.broadcast({"type": "security_events", "data": {"ok": True}}))

    assert live_client.messages == [
        {"type": "security_events", "data": {"ok": True}},
    ]
    assert manager.active_connections == [live_client]
