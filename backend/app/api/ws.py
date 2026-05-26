from fastapi import APIRouter
from fastapi import WebSocket
from fastapi import WebSocketDisconnect

router = APIRouter()


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
        disconnected_connections = []

        for websocket in self.active_connections:
            try:
                await websocket.send_json(message)
            except RuntimeError:
                disconnected_connections.append(websocket)

        for websocket in disconnected_connections:
            self.disconnect(websocket)


manager = WebSocketManager()


@router.websocket("/analyzer")
async def analyzer_websocket(websocket: WebSocket):
    await manager.connect(websocket)

    try:
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        print("Analyzer websocket disconnected")
