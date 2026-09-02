from pydantic import BaseModel


class FrameworkOut(BaseModel):
    framework: str
    framework_version: str
    rule_count: int
    sha256: str


class ComplianceBreakdownOut(BaseModel):
    framework: str
    framework_version: str
    score: int | None
    devices_assessed: int
    pass_count: int
    fail_count: int
    warning_count: int
    not_assessable_count: int
    not_applicable_count: int
