from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require
from app.db import get_db
from app.models import AuditRun, Device, Finding, User
from app.schemas.dashboard import (
    DashboardSummary,
    FrameworkScoreOut,
    RecentFindingOut,
    RiskTrendPointOut,
)
from app.security.permissions import Permission

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_RECENT_FINDINGS_LIMIT = 5
_RISK_TREND_LIMIT = 10


def _org_audit_runs(session: Session, organization_id: int) -> list[AuditRun]:
    runs = session.scalars(select(AuditRun).order_by(AuditRun.created_at.desc()))
    return [run for run in runs if run.configuration.device.organization_id == organization_id]


def _org_findings(session: Session, organization_id: int) -> list[Finding]:
    findings = session.scalars(select(Finding).order_by(Finding.created_at.desc()))

    def in_org(finding: Finding) -> bool:
        result = finding.compliance_result
        if result is None:
            return False
        return result.audit_run.configuration.device.organization_id == organization_id

    return [finding for finding in findings if in_org(finding)]


@router.get("/summary", response_model=DashboardSummary)
def get_summary(
    user: User = Depends(require(Permission.AUDIT_READ)),
    session: Session = Depends(get_db),
) -> DashboardSummary:
    runs = _org_audit_runs(session, user.organization_id)
    findings = _org_findings(session, user.organization_id)
    device_count = len(
        list(session.scalars(select(Device).where(Device.organization_id == user.organization_id)))
    )

    # `runs` is already newest-first.
    security_score = runs[0].score if runs else None
    security_score_previous = runs[1].score if len(runs) > 1 else None
    security_coverage = runs[0].coverage if runs else None

    # One audit run per device: the newest one for that device's configuration.
    latest_run_by_device: dict[int, AuditRun] = {}
    for run in runs:
        device_id = run.configuration.device_id
        if device_id not in latest_run_by_device:
            latest_run_by_device[device_id] = run
    devices_needing_attention = sum(
        1
        for run in latest_run_by_device.values()
        if any(result.status == "FAIL" for result in run.results)
    )

    now = datetime.now(UTC)
    week_ago = now - timedelta(days=7)
    critical_open = [f for f in findings if f.severity == "CRITICAL" and f.triage_status == "open"]
    critical_new_7d = sum(1 for f in critical_open if f.created_at.replace(tzinfo=UTC) >= week_ago)

    # One score per framework: the newest audit run seen for that framework.
    latest_run_by_framework: dict[str, AuditRun] = {}
    for run in runs:
        if run.framework not in latest_run_by_framework:
            latest_run_by_framework[run.framework] = run
    framework_scores = [
        FrameworkScoreOut(
            framework=run.framework,
            framework_version=run.framework_version,
            score=run.score or 0,
            coverage=run.coverage or 0.0,
        )
        for run in latest_run_by_framework.values()
    ]

    risk_trend = [
        RiskTrendPointOut(date=run.created_at.date().isoformat(), score=run.score or 0)
        for run in reversed(runs[:_RISK_TREND_LIMIT])
    ]

    recent_findings = [
        RecentFindingOut(
            id=finding.id,
            title=finding.title,
            severity=finding.severity,
            device_name=finding.compliance_result.audit_run.configuration.device.name,
            audit_run_id=finding.compliance_result.audit_run_id,
        )
        for finding in findings
        if finding.triage_status == "open" and finding.compliance_result is not None
    ][:_RECENT_FINDINGS_LIMIT]

    return DashboardSummary(
        security_score=security_score,
        security_score_previous=security_score_previous,
        security_coverage=security_coverage,
        devices_total=device_count,
        devices_needing_attention=devices_needing_attention,
        critical_findings_open=len(critical_open),
        critical_findings_new_7d=critical_new_7d,
        audits_total=len(runs),
        framework_scores=framework_scores,
        risk_trend=risk_trend,
        recent_findings=recent_findings,
    )
