import asyncio

from fastapi.encoders import jsonable_encoder
from fastapi import WebSocket

from app.core.config import settings


class WebSocketManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket, subprotocol: str | None = None):
        await websocket.accept(subprotocol=subprotocol)
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        encoded_message = jsonable_encoder(message)

        async def send(websocket: WebSocket):
            try:
                await asyncio.wait_for(
                    websocket.send_json(encoded_message),
                    timeout=settings.websocket_send_timeout_seconds,
                )
                return websocket, True
            except (RuntimeError, TimeoutError):
                return websocket, False

        results = await asyncio.gather(
            *(send(websocket) for websocket in list(self.active_connections))
        )
        for websocket, sent in results:
            if not sent:
                self.disconnect(websocket)


manager = WebSocketManager()
