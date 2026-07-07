from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class FlowRule(Base):
    __tablename__ = "flow_rules"
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
    switch_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target: Mapped[str] = mapped_column(String(30), nullable=False)
    action: Mapped[str] = mapped_column(String(30), nullable=False)
    match: Mapped[dict] = mapped_column(JSONB, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    idle_timeout: Mapped[int | None] = mapped_column(Integer, nullable=True)
    hard_timeout: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rate_limit_pps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        server_default=text("'PENDING'"),
    )
    controller_rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    controller_response: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
