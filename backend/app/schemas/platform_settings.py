from pydantic import BaseModel, Field


class PlatformSettingsUpdate(BaseModel):
    congestion_threshold_percent: int = Field(ge=1, le=100)
    automatic_response_enabled: bool
