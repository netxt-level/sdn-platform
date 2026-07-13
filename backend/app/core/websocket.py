import asyncio
import logging

from fastapi.encoders import jsonable_encoder
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return

        encoded_message = jsonable_encoder(message)
        connections = list(self.active_connections)
        results = await asyncio.gather(
            *[
                websocket.send_json(encoded_message)
                for websocket in connections
            ],
            return_exceptions=True,
        )

        for websocket, result in zip(connections, results):
            if isinstance(result, Exception):
                logger.info("WebSocket 전송 실패로 연결을 정리합니다: %s", result)
                self.disconnect(websocket)


manager = WebSocketManager()
