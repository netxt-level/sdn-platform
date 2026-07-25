from typing import Any

from app.core.config import settings
from app.repositories.platform_settings_repository import PlatformSettingsRepository


class PlatformSettingsService:
    def __init__(
        self,
        repository: PlatformSettingsRepository | None = None,
    ):
        self.repository = repository or PlatformSettingsRepository()

    def get(self) -> dict[str, Any]:
        return {
            **self.repository.get(),
            "controller_base_url": settings.controller_base_url,
        }

    def update(self, payload: dict[str, Any]) -> dict[str, Any]:
        updated = self.repository.update(**payload)
        return {
            **updated,
            "controller_base_url": settings.controller_base_url,
        }
