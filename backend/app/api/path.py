from fastapi import APIRouter

from app.services.path_service import PathService

router = APIRouter()
path_service = PathService()


@router.get("/status")
def get_path_status():
    return path_service.get_status()
