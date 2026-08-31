from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.models.base import Base, TimestampMixin
from app.models.device import Configuration


class AuditRun(Base, TimestampMixin):
    __tablename__ = "audit_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    configuration_id: Mapped[int] = mapped_column(ForeignKey("configurations.id"))
    framework: Mapped[str] = mapped_column(String(40))
    framework_version: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default="pending")
    rule_pack_hash: Mapped[str] = mapped_column(String(64))
    engine_version: Mapped[str] = mapped_column(String(40))
    detected_vendor: Mapped[str | None] = mapped_column(String(60), default=None)
    detected_os: Mapped[str | None] = mapped_column(String(60), default=None)
    detection_confidence: Mapped[float | None] = mapped_column(Float, default=None)
    detection_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    vendor_override: Mapped[str | None] = mapped_column(String(60), default=None)
    unknown_constructs: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    parse_warnings: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    score: Mapped[int | None] = mapped_column(Integer, default=None)
    coverage: Mapped[float | None] = mapped_column(Float, default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    configuration: Mapped[Configuration] = relationship()
    controls: Mapped[list["NormalizedControlRow"]] = relationship(back_populates="audit_run")
    results: Mapped[list["ComplianceResultRow"]] = relationship(back_populates="audit_run")


class NormalizedControlRow(Base):
    __tablename__ = "normalized_controls"

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(ForeignKey("audit_runs.id"))
    key: Mapped[str] = mapped_column(String(120), index=True)
    value_json: Mapped[object] = mapped_column(JSON)
    source_lines: Mapped[list[int]] = mapped_column(JSON, default=list)
    excerpt: Mapped[str] = mapped_column(Text, default="")
    parser_confidence: Mapped[float] = mapped_column(Float, default=1.0)
    origin: Mapped[str] = mapped_column(String(20), default="deterministic")

    audit_run: Mapped[AuditRun] = relationship(back_populates="controls")


class ComplianceResultRow(Base):
    __tablename__ = "compliance_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(ForeignKey("audit_runs.id"))
    rule_id: Mapped[str] = mapped_column(String(60), index=True)
    framework: Mapped[str] = mapped_column(String(40))
    framework_version: Mapped[str] = mapped_column(String(40))
    parameter: Mapped[str] = mapped_column(String(120))
    observed_value: Mapped[object] = mapped_column(JSON, default=None)
    expected_value: Mapped[object] = mapped_column(JSON, default=None)
    status: Mapped[str] = mapped_column(String(20), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    evidence_lines: Mapped[list[int]] = mapped_column(JSON, default=list)
    evidence_excerpt: Mapped[str] = mapped_column(Text, default="")

    audit_run: Mapped[AuditRun] = relationship(back_populates="results")
    finding: Mapped["Finding | None"] = relationship(back_populates="compliance_result")


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    compliance_result_id: Mapped[int | None] = mapped_column(
        ForeignKey("compliance_results.id"), default=None
    )
    severity: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(300))
    remediation_id: Mapped[str] = mapped_column(String(60))
    triage_status: Mapped[str] = mapped_column(String(30), default="open")
    notes: Mapped[str] = mapped_column(Text, default="")

    compliance_result: Mapped[ComplianceResultRow | None] = relationship(back_populates="finding")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(ForeignKey("audit_runs.id"))
    blob_key: Mapped[str] = mapped_column(String(255))
    generated_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    audit_run: Mapped[AuditRun] = relationship()
