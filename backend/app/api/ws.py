from fastapi import APIRouter, Depends
from fastapi import WebSocket
from fastapi import WebSocketDisconnect

from app.core.auth import issue_websocket_token
from app.core.auth import require_admin_api_key
from app.core.auth import verify_websocket_token
from app.core.config import settings
from app.core.websocket import manager

router = APIRouter()


@router.post("/token", dependencies=[Depends(require_admin_api_key)])
def create_websocket_token():
    token, expires_at = issue_websocket_token()
    return {"token": token, "expires_at": expires_at}


@router.websocket("/analyzer")
async def analyzer_websocket(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    protocols = [
        value.strip()
        for value in websocket.headers.get("sec-websocket-protocol", "").split(",")
        if value.strip()
    ]
    token = protocols[1] if len(protocols) == 2 and protocols[0] == "sdn-realtime" else ""
    origin_allowed = origin in settings.websocket_allowed_origins
    if settings.allow_insecure_dev_auth and origin is None:
        origin_allowed = True
    if not origin_allowed or not verify_websocket_token(token):
        await websocket.close(code=1008)
        return

    await manager.connect(websocket, subprotocol="sdn-realtime")

    try:
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        manager.disconnect(websocket)
