from sqlalchemy.orm import Session

from app.models import AuditEvent


def record_event(
    session: Session,
    *,
    action: str,
    user_id: int | None = None,
    resource: str = "",
    ip: str = "",
    result: str = "SUCCESS",
) -> None:
    """Append a security-relevant event. Never records configuration content."""
    session.add(AuditEvent(user_id=user_id, action=action, resource=resource, ip=ip, result=result))
