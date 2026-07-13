import logging

from fastapi import APIRouter
from fastapi import WebSocket
from fastapi import WebSocketDisconnect

from app.core.websocket import manager

router = APIRouter()
logger = logging.getLogger(__name__)


@router.websocket("/analyzer")
async def analyzer_websocket(websocket: WebSocket):
    await manager.connect(websocket)

    try:
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Analyzer websocket disconnected")

    except Exception:
        manager.disconnect(websocket)
        logger.exception("Analyzer websocket connection failed")
