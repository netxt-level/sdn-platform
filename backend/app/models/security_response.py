from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class SecurityResponse(Base):
    __tablename__ = "security_responses"
    __table_args__ = {"schema": "sdn_controller"}

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    source_event_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    source_event_fingerprint: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
    analyzer_id: Mapped[str] = mapped_column(String(30), nullable=False)
    attack_category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    attack_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(30), nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(String(50), nullable=True)
    response_action: Mapped[str] = mapped_column(String(50), nullable=False)
    response_level: Mapped[str | None] = mapped_column(String(30), nullable=True)
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        server_default=text("'PENDING'"),
    )
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitigation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    response_payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    detected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
        onupdate=func.now(),
    )
