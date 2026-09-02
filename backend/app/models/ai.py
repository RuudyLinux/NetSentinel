from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.models.base import Base, TimestampMixin
from app.models.org import User


class AiInterpretation(Base, TimestampMixin):
    """A human-reviewable AI suggestion for one unrecognized config line.

    Advisory only — approving one records the human's decision for evidence/audit
    trail purposes. It does not feed back into re-scoring the audit or change how
    future configs are parsed; that "learned mappings become active" loop is a
    bigger, separate piece of work.
    """

    __tablename__ = "ai_interpretations"
    __table_args__ = (UniqueConstraint("audit_run_id", "construct_index"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(ForeignKey("audit_runs.id"))
    # Position of this construct in AuditRun.unknown_constructs — stable for the
    # life of the run, since that list is written once and never mutated.
    construct_index: Mapped[int] = mapped_column(Integer)
    model: Mapped[str] = mapped_column(String(80))
    interpretation: Mapped[str] = mapped_column(Text)
    suggested_parameter: Mapped[str | None] = mapped_column(String(120), default=None)
    suggested_value: Mapped[object] = mapped_column(JSON, default=None)
    confidence: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    reviewed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), default=None)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    notes: Mapped[str] = mapped_column(Text, default="")

    reviewed_by: Mapped[User | None] = relationship()
