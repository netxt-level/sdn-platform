from fastapi import APIRouter
from fastapi import WebSocket
from fastapi import WebSocketDisconnect

router = APIRouter()


@router.websocket("/analyzer")
async def analyzer_websocket(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            message = await websocket.receive_text()

            await websocket.send_json({
                "type": "echo",
                "message": message,
            })

    except WebSocketDisconnect:
        print("Analyzer websocket disconnected")
