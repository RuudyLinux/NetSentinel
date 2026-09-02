from datetime import datetime

from pydantic import BaseModel


class AdminUserOut(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    created_at: datetime


class RoleOut(BaseModel):
    name: str
    permissions: list[str]


class AuditLogEntryOut(BaseModel):
    id: int
    created_at: datetime
    user_email: str
    action: str
    resource: str
    result: str
    ip: str


class AuditLogPageOut(BaseModel):
    entries: list[AuditLogEntryOut]
    next_before_id: int | None
