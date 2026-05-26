from fastapi import APIRouter

router = APIRouter()


@router.get("/status")
def get_analyzer_status():
    return {
        "items": [
            {
                "analyzer_id": "analyzer-1",
                "status": "running",
                "interface": "en0",
                "backend_connected": True,
            }
        ],
    }
