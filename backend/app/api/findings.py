from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.audit_log import record_event
from app.config import settings
from app.db import get_db
from app.models import ComplianceResultRow, Finding, User
from app.schemas.findings import (
    FindingDetail,
    FindingSummary,
    RemediationOut,
    TriageRequest,
)
from app.security.permissions import Permission
from app.services.compliance.rules import load_all_packs
from app.services.remediation.packs import load_remediations

router = APIRouter(prefix="/findings", tags=["findings"])


def _load(session: Session, finding_id: int, user: User) -> tuple[Finding, ComplianceResultRow]:
    finding = session.get(Finding, finding_id)
    if finding is None or finding.compliance_result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    result = finding.compliance_result
    if result.audit_run.configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return finding, result


def _summary(finding: Finding, result: ComplianceResultRow) -> FindingSummary:
    device = result.audit_run.configuration.device
    return FindingSummary(
        id=finding.id,
        audit_run_id=result.audit_run_id,
        device_id=device.id,
        device_name=device.name,
        rule_id=result.rule_id,
        title=finding.title,
        severity=finding.severity,
        status=result.status,
        parameter=result.parameter,
        triage_status=finding.triage_status,
    )


@router.get("", response_model=list[FindingSummary])
def list_findings(
    audit_id: int | None = None,
    severity: str | None = None,
    triage_status: str | None = None,
    framework: str | None = None,
    user: User = Depends(require(Permission.FINDING_READ)),
    session: Session = Depends(get_db),
) -> list[FindingSummary]:
    statement = select(Finding).join(Finding.compliance_result)
    if audit_id is not None:
        statement = statement.where(ComplianceResultRow.audit_run_id == audit_id)
    if severity is not None:
        statement = statement.where(Finding.severity == severity.upper())
    if triage_status is not None:
        statement = statement.where(Finding.triage_status == triage_status)
    if framework is not None:
        statement = statement.where(ComplianceResultRow.framework == framework.upper())

    findings = session.scalars(statement.order_by(Finding.id))
    return [
        _summary(finding, finding.compliance_result)
        for finding in findings
        if finding.compliance_result is not None
        and finding.compliance_result.audit_run.configuration.device.organization_id
        == user.organization_id
    ]


@router.get("/{finding_id}", response_model=FindingDetail)
def read_finding(
    finding_id: int,
    user: User = Depends(require(Permission.FINDING_READ)),
    session: Session = Depends(get_db),
) -> FindingDetail:
    finding, result = _load(session, finding_id, user)
    run = result.audit_run

    rules = {rule.id: rule for pack in load_all_packs(settings.rules_dir) for rule in pack.rules}
    rule = rules[result.rule_id]
    remediation = load_remediations(settings.mappings_dir)[finding.remediation_id]

    return FindingDetail(
        **_summary(finding, result).model_dump(),
        framework=result.framework,
        framework_version=result.framework_version,
        rule_pack_hash=run.rule_pack_hash,
        configuration_sha256=run.configuration.sha256,
        description=rule.description,
        impact=rule.impact,
        observed_value=result.observed_value,
        expected_value=result.expected_value,
        evidence_lines=result.evidence_lines,
        evidence_excerpt=result.evidence_excerpt,
        notes=finding.notes,
        remediation=RemediationOut(
            id=remediation.id,
            title=remediation.title,
            cli=remediation.cli,
            verification=remediation.verification,
            rollback=remediation.rollback,
            notes=remediation.notes,
            banner=remediation.banner,
        ),
    )


@router.patch("/{finding_id}", response_model=FindingSummary)
def triage_finding(
    finding_id: int,
    payload: TriageRequest,
    request: Request,
    user: User = Depends(require(Permission.FINDING_TRIAGE)),
    session: Session = Depends(get_db),
) -> FindingSummary:
    finding, result = _load(session, finding_id, user)
    if payload.triage_status is not None:
        finding.triage_status = payload.triage_status
    if payload.notes is not None:
        finding.notes = payload.notes

    record_event(
        session,
        action="TRIAGE_FINDING",
        user_id=user.id,
        resource=str(finding.id),
        ip=client_ip(request),
    )
    session.commit()
    return _summary(finding, result)
