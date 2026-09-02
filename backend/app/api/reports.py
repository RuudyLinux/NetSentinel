from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.audit_log import record_event
from app.config import settings
from app.db import get_db
from app.models import AuditRun, ComplianceResultRow, Finding, Report, User
from app.schemas.reports import ReportOut, ReportSummary
from app.security.permissions import Permission
from app.services.remediation.packs import load_remediations
from app.services.reporting.pdf import build_device_report
from app.storage.base import StorageBackend
from app.storage.local import get_storage

router = APIRouter(tags=["reports"])


@router.get("/reports", response_model=list[ReportSummary])
def list_reports(
    user: User = Depends(require(Permission.REPORT_READ)),
    session: Session = Depends(get_db),
) -> list[ReportSummary]:
    reports = session.scalars(select(Report).order_by(Report.id.desc()))
    return [
        ReportSummary(
            id=report.id,
            audit_run_id=report.audit_run_id,
            device_name=report.audit_run.configuration.device.name,
            framework=report.audit_run.framework,
            framework_version=report.audit_run.framework_version,
            created_at=report.created_at,
        )
        for report in reports
        if report.audit_run.configuration.device.organization_id == user.organization_id
    ]


@router.post(
    "/audits/{audit_id}/report", response_model=ReportOut, status_code=status.HTTP_201_CREATED
)
def generate_report(
    audit_id: int,
    request: Request,
    user: User = Depends(require(Permission.REPORT_GENERATE)),
    session: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
) -> ReportOut:
    run = session.get(AuditRun, audit_id)
    if run is None or run.configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Audit not found")

    pairs = [
        (finding, finding.compliance_result)
        for finding in session.scalars(
            select(Finding)
            .join(Finding.compliance_result)
            .where(ComplianceResultRow.audit_run_id == run.id)
            .order_by(Finding.severity, Finding.id)
        )
        if finding.compliance_result is not None
    ]

    pdf = build_device_report(run, pairs, load_remediations(settings.mappings_dir))
    blob_key = f"reports/audit-{run.id}.pdf"
    storage.put(blob_key, pdf)

    report = Report(audit_run_id=run.id, blob_key=blob_key, generated_by_id=user.id)
    session.add(report)
    session.flush()
    record_event(
        session,
        action="GENERATE_REPORT",
        user_id=user.id,
        resource=str(run.id),
        ip=client_ip(request),
    )
    session.commit()
    return ReportOut(id=report.id, audit_run_id=run.id)


@router.get("/reports/{report_id}")
def download_report(
    report_id: int,
    user: User = Depends(require(Permission.REPORT_READ)),
    session: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
) -> Response:
    report = session.get(Report, report_id)
    if (
        report is None
        or report.audit_run.configuration.device.organization_id != user.organization_id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")

    filename = f"netsentinel-audit-{report.audit_run_id}.pdf"
    return Response(
        content=storage.get(report.blob_key),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
