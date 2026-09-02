from pydantic import BaseModel


class FrameworkScoreOut(BaseModel):
    framework: str
    framework_version: str
    score: int
    coverage: float


class RiskTrendPointOut(BaseModel):
    date: str
    score: int


class RecentFindingOut(BaseModel):
    id: int
    title: str
    severity: str
    device_name: str
    audit_run_id: int


class DashboardSummary(BaseModel):
    security_score: int | None
    security_score_previous: int | None
    security_coverage: float | None
    devices_total: int
    devices_needing_attention: int
    critical_findings_open: int
    critical_findings_new_7d: int
    audits_total: int
    framework_scores: list[FrameworkScoreOut]
    risk_trend: list[RiskTrendPointOut]
    recent_findings: list[RecentFindingOut]
