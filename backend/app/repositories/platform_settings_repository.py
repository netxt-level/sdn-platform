from datetime import datetime
from datetime import timezone
from typing import Any

from app.db.session import SessionLocal
from app.models.platform_setting import PlatformSetting


DEFAULT_SETTINGS_ID = "default"


def _to_dict(settings: PlatformSetting) -> dict[str, Any]:
    return {
        "congestion_threshold_percent": settings.congestion_threshold_percent,
        "automatic_response_enabled": settings.automatic_response_enabled,
        "updated_at": settings.updated_at,
    }


class PlatformSettingsRepository:
    def get(self) -> dict[str, Any]:
        with SessionLocal.begin() as session:
            settings = session.get(PlatformSetting, DEFAULT_SETTINGS_ID)
            if settings is None:
                settings = PlatformSetting(id=DEFAULT_SETTINGS_ID)
                session.add(settings)
                session.flush()
            return _to_dict(settings)

    def update(
        self,
        *,
        congestion_threshold_percent: int,
        automatic_response_enabled: bool,
    ) -> dict[str, Any]:
        with SessionLocal.begin() as session:
            settings = session.get(PlatformSetting, DEFAULT_SETTINGS_ID)
            if settings is None:
                settings = PlatformSetting(id=DEFAULT_SETTINGS_ID)
                session.add(settings)

            settings.congestion_threshold_percent = congestion_threshold_percent
            settings.automatic_response_enabled = automatic_response_enabled
            settings.updated_at = datetime.now(timezone.utc)
            session.flush()
            return _to_dict(settings)
