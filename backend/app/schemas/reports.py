from datetime import datetime

from pydantic import BaseModel


class ReportOut(BaseModel):
    id: int
    audit_run_id: int


class ReportSummary(BaseModel):
    id: int
    audit_run_id: int
    device_name: str
    framework: str
    framework_version: str
    created_at: datetime
