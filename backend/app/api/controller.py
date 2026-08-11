from fastapi import APIRouter

from app.clients.controller import ControllerClient
from app.clients.controller import ControllerClientError


router = APIRouter()
controller_client = ControllerClient()


@router.get("/status")
def get_controller_status():
    try:
        health = controller_client.get_health()
    except ControllerClientError as error:
        return {
            "connected": False,
            "ready": False,
            "connected_switches": 0,
            "error": str(error),
        }

    connected_switches = int(health.get("connected_switches") or 0)
    ready = str(health.get("status", "")).lower() in {"ok", "ready"}
    return {
        "connected": ready,
        "ready": ready,
        "connected_switches": connected_switches,
        "controller": health,
        "error": None,
    }
