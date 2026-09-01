from pydantic import BaseModel


class ReportOut(BaseModel):
    id: int
    audit_run_id: int
