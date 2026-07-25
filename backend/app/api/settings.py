from fastapi import APIRouter

from app.schemas.platform_settings import PlatformSettingsUpdate
from app.services.platform_settings_service import PlatformSettingsService


router = APIRouter()
platform_settings_service = PlatformSettingsService()


@router.get("")
def get_platform_settings():
    return platform_settings_service.get()


@router.put("")
def update_platform_settings(payload: PlatformSettingsUpdate):
    return platform_settings_service.update(payload.model_dump())
