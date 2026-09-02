from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require
from app.config import settings
from app.db import get_db
from app.models import AuditRun, User
from app.schemas.frameworks import ComplianceBreakdownOut, FrameworkOut
from app.security.permissions import Permission
from app.services.compliance.rules import load_all_packs

router = APIRouter(prefix="/frameworks", tags=["frameworks"])


@router.get("", response_model=list[FrameworkOut])
def list_frameworks(
    _: User = Depends(require(Permission.AUDIT_READ)),
) -> list[FrameworkOut]:
    return [
        FrameworkOut(
            framework=pack.framework,
            framework_version=pack.framework_version,
            rule_count=len(pack.rules),
            sha256=pack.sha256,
        )
        for pack in load_all_packs(settings.rules_dir)
    ]


@router.get("/{framework}/rules")
def list_rules(
    framework: str,
    _: User = Depends(require(Permission.AUDIT_READ)),
) -> list[dict[str, object]]:
    for pack in load_all_packs(settings.rules_dir):
        if pack.framework.upper() == framework.upper():
            return [rule.model_dump(mode="json") for rule in pack.rules]
    raise HTTPException(status.HTTP_404_NOT_FOUND, "Framework not found")


@router.get("/{framework}/compliance", response_model=ComplianceBreakdownOut)
def get_compliance(
    framework: str,
    user: User = Depends(require(Permission.AUDIT_READ)),
    session: Session = Depends(get_db),
) -> ComplianceBreakdownOut:
    """Org-wide compliance for one framework: the newest audit run per device that has
    ever been audited against it, aggregated. Older runs for a device are superseded —
    this reflects current posture, not audit history."""
    pack = next(
        (p for p in load_all_packs(settings.rules_dir) if p.framework.upper() == framework.upper()),
        None,
    )
    if pack is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Framework not found")

    runs = session.scalars(select(AuditRun).order_by(AuditRun.created_at.desc()))
    latest_by_device: dict[int, AuditRun] = {}
    for run in runs:
        device = run.configuration.device
        same_org = device.organization_id == user.organization_id
        same_framework = run.framework.upper() == pack.framework.upper()
        if same_org and same_framework and device.id not in latest_by_device:
            latest_by_device[device.id] = run

    assessed = list(latest_by_device.values())
    counts: Counter[str] = Counter()
    for run in assessed:
        counts.update(result.status for result in run.results)

    scores = [run.score for run in assessed if run.score is not None]
    score = round(sum(scores) / len(scores)) if scores else None

    return ComplianceBreakdownOut(
        framework=pack.framework,
        framework_version=pack.framework_version,
        score=score,
        devices_assessed=len(assessed),
        pass_count=counts["PASS"],
        fail_count=counts["FAIL"],
        warning_count=counts["WARNING"],
        not_assessable_count=counts["NOT_ASSESSABLE"],
        not_applicable_count=counts["NOT_APPLICABLE"],
    )
