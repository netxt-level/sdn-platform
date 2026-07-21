from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class PlatformSetting(Base):
    __tablename__ = "platform_settings"
    __table_args__ = {"schema": "sdn_controller"}

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    congestion_threshold_percent: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("70"),
    )
    automatic_response_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("true"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
