from dataclasses import dataclass, field
from enum import StrEnum

from app.domain.controls import ControlPrimitive, ControlValue


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_ASSESSABLE = "NOT_ASSESSABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class ComplianceResult:
    rule_id: str
    framework: str
    framework_version: str
    parameter: str
    observed_value: ControlPrimitive
    expected_value: ControlPrimitive
    status: Status
    severity: Severity
    evidence: ControlValue | None = None


@dataclass(frozen=True)
class PostureScore:
    score: int
    coverage: float
    fail_counts: dict[Severity, int] = field(default_factory=dict)
    assessable: int = 0
    not_assessable: int = 0
