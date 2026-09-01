from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.audit_log import record_event
from app.db import get_db
from app.domain.results import Severity
from app.models import AuditRun, ComplianceResultRow, Configuration, User
from app.schemas.audits import (
    AuditDetail,
    AuditRequest,
    AuditSummary,
    ControlOut,
    DetectionOut,
    ResultOut,
    UnknownOut,
)
from app.security.permissions import Permission
from app.services.audit.runner import DetectionConfirmationRequired, UnknownFramework, run_audit
from app.storage.base import StorageBackend
from app.storage.local import get_storage

router = APIRouter(prefix="/audits", tags=["audits"])


def _fail_counts(session: Session, run: AuditRun) -> dict[str, int]:
    rows = session.scalars(
        select(ComplianceResultRow).where(
            ComplianceResultRow.audit_run_id == run.id, ComplianceResultRow.status == "FAIL"
        )
    )
    counts = {str(severity): 0 for severity in Severity}
    for row in rows:
        counts[row.severity] += 1
    return counts


def _summary(session: Session, run: AuditRun) -> AuditSummary:
    return AuditSummary(
        id=run.id,
        configuration_id=run.configuration_id,
        device_name=run.configuration.device.name,
        framework=run.framework,
        framework_version=run.framework_version,
        status=run.status,
        score=run.score,
        coverage=run.coverage,
        rule_pack_hash=run.rule_pack_hash,
        engine_version=run.engine_version,
        detection=DetectionOut(
            vendor=run.detected_vendor,
            os=run.detected_os,
            confidence=run.detection_confidence,
            reasons=run.detection_reasons,
            override=run.vendor_override,
        ),
        fail_counts=_fail_counts(session, run),
    )


@router.post("", response_model=AuditSummary, status_code=status.HTTP_201_CREATED)
def create_audit(
    payload: AuditRequest,
    request: Request,
    user: User = Depends(require(Permission.AUDIT_RUN)),
    session: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
) -> AuditSummary:
    configuration = session.get(Configuration, payload.configuration_id)
    if configuration is None or configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Configuration not found")

    try:
        run = run_audit(session, storage, configuration, payload.framework, payload.vendor_override)
    except DetectionConfirmationRequired as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "message": "Device detection requires manual confirmation",
                "confidence": exc.identity.confidence,
                "reasons": exc.identity.reasons,
                "candidate_vendor": exc.identity.vendor,
            },
        ) from exc
    except UnknownFramework as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    record_event(
        session,
        action="START_AUDIT",
        user_id=user.id,
        resource=str(run.id),
        ip=client_ip(request),
    )
    session.commit()
    return _summary(session, run)


@router.get("", response_model=list[AuditSummary])
def list_audits(
    user: User = Depends(require(Permission.AUDIT_READ)),
    session: Session = Depends(get_db),
) -> list[AuditSummary]:
    runs = session.scalars(select(AuditRun).order_by(AuditRun.id.desc()))
    return [
        _summary(session, run)
        for run in runs
        if run.configuration.device.organization_id == user.organization_id
    ]


@router.get("/{audit_id}", response_model=AuditDetail)
def read_audit(
    audit_id: int,
    user: User = Depends(require(Permission.AUDIT_READ)),
    session: Session = Depends(get_db),
) -> AuditDetail:
    run = session.get(AuditRun, audit_id)
    if run is None or run.configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Audit not found")

    return AuditDetail(
        **_summary(session, run).model_dump(),
        controls=[
            ControlOut(
                key=row.key,
                value=row.value_json,
                source_lines=row.source_lines,
                excerpt=row.excerpt,
                parser_confidence=row.parser_confidence,
                origin=row.origin,
            )
            for row in run.controls
        ],
        results=[
            ResultOut(
                rule_id=row.rule_id,
                parameter=row.parameter,
                observed_value=row.observed_value,
                expected_value=row.expected_value,
                status=row.status,
                severity=row.severity,
                evidence_lines=row.evidence_lines,
                evidence_excerpt=row.evidence_excerpt,
            )
            for row in run.results
        ],
        unknown_constructs=[UnknownOut(**item) for item in run.unknown_constructs],
        parse_warnings=run.parse_warnings,
    )
