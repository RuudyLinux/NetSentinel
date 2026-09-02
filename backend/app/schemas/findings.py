from typing import Literal

from pydantic import BaseModel

TriageStatus = Literal["open", "accepted_risk", "false_positive", "resolved"]


class RemediationOut(BaseModel):
    id: str
    title: str
    cli: str
    verification: str
    rollback: str
    notes: str
    banner: str


class FindingSummary(BaseModel):
    id: int
    audit_run_id: int
    device_id: int
    device_name: str
    rule_id: str
    title: str
    severity: str
    status: str
    parameter: str
    triage_status: str


class FindingDetail(FindingSummary):
    framework: str
    framework_version: str
    rule_pack_hash: str
    configuration_sha256: str
    description: str
    impact: str
    observed_value: object
    expected_value: object
    evidence_lines: list[int]
    evidence_excerpt: str
    notes: str
    remediation: RemediationOut


class TriageRequest(BaseModel):
    triage_status: TriageStatus | None = None
    notes: str | None = None
