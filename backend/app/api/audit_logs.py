from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require
from app.db import get_db
from app.models import AuditEvent, User
from app.schemas.users import AuditLogEntryOut, AuditLogPageOut
from app.security.permissions import Permission

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


@router.get("", response_model=AuditLogPageOut)
def list_audit_logs(
    limit: int = _DEFAULT_LIMIT,
    before_id: int | None = None,
    user: User = Depends(require(Permission.USER_ADMIN)),
    session: Session = Depends(get_db),
) -> AuditLogPageOut:
    """Org-scoped security event log, newest first.

    Events with no attributable user (e.g. a failed login against an unknown email —
    AuditEvent.user_id is None by design, see api/auth.py) are excluded: the inner join
    to User is what enforces the org boundary, and an event that can't be joined to a
    user can't be attributed to an org either. Paginated with a before_id cursor since,
    unlike every other list endpoint here, this table is expected to grow without bound.
    """
    page_size = max(1, min(limit, _MAX_LIMIT))
    statement = (
        select(AuditEvent, User.email)
        .join(User, AuditEvent.user_id == User.id)
        .where(User.organization_id == user.organization_id)
        .order_by(AuditEvent.id.desc())
    )
    if before_id is not None:
        statement = statement.where(AuditEvent.id < before_id)

    rows = session.execute(statement.limit(page_size + 1)).all()
    has_more = len(rows) > page_size
    page = rows[:page_size]

    entries = [
        AuditLogEntryOut(
            id=event.id,
            created_at=event.created_at,
            user_email=email,
            action=event.action,
            resource=event.resource,
            result=event.result,
            ip=event.ip,
        )
        for event, email in page
    ]
    return AuditLogPageOut(
        entries=entries,
        next_before_id=entries[-1].id if has_more and entries else None,
    )
