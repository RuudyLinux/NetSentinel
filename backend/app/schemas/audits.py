from pydantic import BaseModel


class AuditRequest(BaseModel):
    configuration_id: int
    framework: str = "CIS"
    vendor_override: str | None = None


class DetectionOut(BaseModel):
    vendor: str | None
    os: str | None
    confidence: float | None
    reasons: list[str]
    override: str | None = None


class ControlOut(BaseModel):
    key: str
    value: object
    source_lines: list[int]
    excerpt: str
    parser_confidence: float
    origin: str


class ResultOut(BaseModel):
    rule_id: str
    parameter: str
    observed_value: object
    expected_value: object
    status: str
    severity: str
    evidence_lines: list[int]
    evidence_excerpt: str


class UnknownOut(BaseModel):
    text: str
    lineno: int
    block: str | None = None


class AuditSummary(BaseModel):
    id: int
    configuration_id: int
    device_name: str
    framework: str
    framework_version: str
    status: str
    score: int | None
    coverage: float | None
    rule_pack_hash: str
    engine_version: str
    detection: DetectionOut
    fail_counts: dict[str, int]


class AuditDetail(AuditSummary):
    controls: list[ControlOut]
    results: list[ResultOut]
    unknown_constructs: list[UnknownOut]
    parse_warnings: list[dict[str, object]]
